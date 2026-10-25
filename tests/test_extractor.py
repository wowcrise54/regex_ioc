"""Тесты извлечения. Образцы синтетические, но воспроизводят приёмы из реальных
бюллетеней: обезвреживание (hxxp, [.], [:]), переносы строк внутри IoC, таблицы."""

import csv
import io
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_extractor.exporters import export_csv, export_per_type, export_txt
from ioc_extractor.extractor import Options, defang, extract, refang
from ioc_extractor.readers import read_document

SHA256_A = "a" * 10 + "0123456789abcdef" * 3 + "bcdef4"  # 64
MD5_A = "0123456789abcdef0123456789abcdef"[::-1]

SAMPLE = f"""
Тверская ул., e-mail: info@minobrnauki.gov.ru, http://www.minobrnauki.gov.ru
ограничение обращений к следующим адресам:
45[.]143[.]166[.]100;
hxxps[:]//bitbucket[.]org/user1/repo/downloads/file[.]txt;
hxxps[:]//raw[.]githubusercontent[.]com/someone/audit/main/img_test.jp
g?14441723.
hxxps[:]//evil-host[.]petition-change[.]org/for-
imperator-and-great.
ограничение обращений к адресу credit -
bestsale[.]ru, используя схему доступа.
индикаторов компрометации (sha256):
{SHA256_A[:61]}
{SHA256_A[61:]}.
индикаторов компрометации (md5):
{MD5_A};
Антивирус Dr.Web Security Space, файл «Соглашение. pdf.exe», «EUR 510,100.com».
rule-covers[.]gl[.]at[.]ply[.]gg brostoplookingformyc2-
21003[.]portmap[.]io
hxxp[:]//103[.]5[.]144[.]50[:]8000/rev[.]exe;
hxxps[:]//kg[.]example-bad[.]com/Docs2025/Audits/FinalReport/
ZKNS_027841/Deklaratsii/
hxxp[:]//kg[.]example-bad[.]com/privacy/NSM[.]lic
attacker[@]mail[.]ru и admin[at]bad-domain[.]com
внутренний адрес 192.168.1.10 и г.Москва, см.сайт
"""


def values(iocs, ioc_type):
    return {i.value for i in iocs if i.type == ioc_type}


def test_refang():
    assert refang("hxxps[:]//a[.]b[.]com") == "https://a.b.com"
    assert refang("user[at]mail(.)ru") == "user@mail.ru"
    assert refang("hXXp://x[dot]org") == "http://x.org"


def test_defang_roundtrip():
    assert defang("https://a.b.com/x.txt", "url") == "hxxps[:]//a[.]b[.]com/x.txt"
    assert defang("1.2.3.4", "ip") == "1[.]2[.]3[.]4"
    assert defang("a@b.ru", "email") == "a[@]b[.]ru"
    assert refang(defang("https://a.b.com/x", "url")) == "https://a.b.com/x"


def test_sample():
    iocs = extract(SAMPLE)
    urls = values(iocs, "url")
    assert urls == {
        "https://bitbucket.org/user1/repo/downloads/file.txt",
        "https://raw.githubusercontent.com/someone/audit/main/img_test.jpg?14441723",
        "https://evil-host.petition-change.org/for-imperator-and-great",
        "http://103.5.144.50:8000/rev.exe",
        "https://kg.example-bad.com/Docs2025/Audits/FinalReport/ZKNS_027841/Deklaratsii/",
        "http://kg.example-bad.com/privacy/NSM.lic",
    }
    assert values(iocs, "ip") == {"45.143.166.100"}
    assert values(iocs, "hash") == {SHA256_A, MD5_A}
    assert values(iocs, "domain") == {
        "credit-bestsale.ru",
        "rule-covers.gl.at.ply.gg",
        "brostoplookingformyc2-21003.portmap.io",
    }
    assert values(iocs, "email") == {"attacker@mail.ru", "admin@bad-domain.com"}
    assert all(i.defanged for i in iocs if i.type != "hash")


def test_hash_subtypes_and_context():
    iocs = {i.value: i for i in extract(SAMPLE)}
    assert iocs[SHA256_A].subtype == "sha256"
    assert iocs[MD5_A].subtype == "md5"
    assert "45[.]143[.]166[.]100" in iocs["45.143.166.100"].context


def test_two_column_md5_table_not_joined():
    a, b, c = MD5_A, MD5_A[::-1], MD5_A[16:] + MD5_A[:16]
    iocs = extract(f"{a} {b}\n{c}\n")
    assert values(iocs, "hash") == {a, b, c}


def test_options():
    text = "evil[.]com good.example.org 10.0.0.1 8.8.8.8 hxxp://x[.]ru/a"
    assert values(extract(text, Options(defanged_only=True, exclusions=())), "domain") == {"evil.com"}
    assert values(extract(text, Options(exclusions=("example.org",))), "domain") == {"evil.com"}
    assert values(extract(text, Options(exclusions=())), "ip") == {"8.8.8.8"}
    assert values(extract(text, Options(skip_private_ip=False, exclusions=())), "ip") == {"8.8.8.8", "10.0.0.1"}
    assert "x.ru" in values(extract(text, Options(include_url_hosts=True)), "domain")
    assert values(extract(text, Options(exclusions=("8.0.0.0/8",))), "ip") == set()
    assert {i.type for i in extract(text, Options(types=frozenset({"url"})))} == {"url"}


def test_ipv6_and_sha1():
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    iocs = extract(f"c2 2001:db8:85a3::8a2e:370:7334 sha1 {sha1} время 12:02:33")
    assert values(iocs, "hash") == {sha1}
    # 2001:db8::/32 — документационный диапазон, считается служебным
    assert values(extract("2606:4700:4700::1111"), "ip") == {"2606:4700:4700::1111"}


def test_no_join_for_csv_like_text():
    text = "http://a.com/path\n12345,foo\n"
    assert values(extract(text, join_wrapped=False), "url") == {"http://a.com/path"}


def test_exports(tmp_path=None):
    iocs = extract(SAMPLE)
    d = tmp_path or tempfile.mkdtemp()
    export_txt(iocs, os.path.join(d, "all.txt"), defanged=True)
    content = open(os.path.join(d, "all.txt"), encoding="utf-8").read()
    assert "# URL (6)" in content and "45[.]143[.]166[.]100" in content
    export_csv(iocs, os.path.join(d, "all.csv"))
    rows = list(csv.DictReader(io.open(os.path.join(d, "all.csv"), encoding="utf-8-sig"), delimiter=";"))
    assert len(rows) == len(iocs) and rows[0]["type"] == "url"
    files = export_per_type(iocs, d, "doc", "txt")
    assert {os.path.basename(f) for f in files} == {f"doc_{t}.txt" for t in ("url", "domain", "ip", "email", "hash")}
    assert open(os.path.join(d, "doc_ip.txt"), encoding="utf-8").read() == "45.143.166.100\n"


def test_read_docx(tmp_path=None):
    d = tmp_path or tempfile.mkdtemp()
    path = os.path.join(d, "t.docx")
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    doc = (f'<w:document xmlns:w="{w}"><w:body>'
           '<w:p><w:r><w:t>Адрес: evil[.]com</w:t></w:r></w:p>'
           '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>1.2.3.4</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
           '</w:body></w:document>')
    rels = ('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"'
            ' Target="http://hidden-link.net/x" TargetMode="External"/></Relationships>')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("word/document.xml", doc)
        z.writestr("word/_rels/document.xml.rels", rels)
    text = read_document(path).text
    iocs = extract(text)
    assert values(iocs, "domain") == {"evil.com"}
    assert values(iocs, "ip") == {"1.2.3.4"}
    assert values(iocs, "url") == {"http://hidden-link.net/x"}


def test_read_cp1251_txt(tmp_path=None):
    d = tmp_path or tempfile.mkdtemp()
    path = os.path.join(d, "t.txt")
    with open(path, "wb") as f:
        f.write("Сервер управления: bad[.]ru".encode("cp1251"))
    doc = read_document(path)
    assert doc.kind == "txt" and values(extract(doc.text), "domain") == {"bad.ru"}
