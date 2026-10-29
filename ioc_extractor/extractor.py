"""Извлечение индикаторов компрометации (IoC) из текста.

Поддерживаемые типы: email, url, ip (IPv4/IPv6), hash (md5/sha1/sha256/sha512), domain.
Текст предварительно «рефангуется» (hxxp -> http, [.] -> . и т.д.), а IoC,
разорванные переносом строки (типично для PDF), склеиваются эвристиками.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .tlds import TLDS

IOC_TYPES = ("url", "domain", "ip", "email", "hash")
TYPE_TITLES = {
    "url": "URL",
    "domain": "Домен",
    "ip": "IP",
    "email": "Email",
    "hash": "Хэш",
}

HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# TLD, совпадающие с распространёнными расширениями файлов: без явного
# обезвреживания ([.]) такие «домены» почти всегда оказываются именами файлов.
FILE_EXT_TLDS = frozenset({"zip", "mov", "py", "sh", "pl", "md", "rs", "cab", "so", "ps", "cs", "exe"})

DEFAULT_EXCLUSIONS = (
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "minobrnauki.gov.ru",
    "dr.web",
)


@dataclass
class IoC:
    type: str
    value: str
    subtype: str = ""
    defanged: bool = False
    count: int = 1
    sources: list[str] = field(default_factory=list)
    context: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return self.type, self.value


@dataclass
class Options:
    types: frozenset[str] = frozenset(IOC_TYPES)
    join_wrapped: bool = True
    defanged_only: bool = False
    include_url_hosts: bool = False
    skip_private_ip: bool = True
    exclusions: tuple[str, ...] = DEFAULT_EXCLUSIONS


# --------------------------------------------------------------------------
# Текст с картой смещений на оригинал (нужна для контекста и признака defang)
# --------------------------------------------------------------------------

class MappedText:
    def __init__(self, text: str):
        self.original = text
        self.text = text
        self.map: list[int] | None = None  # None — тождественное отображение

    def sub(self, pattern: re.Pattern, repl: str | Callable[[re.Match], str]) -> int:
        out: list[str] = []
        idx: list[int] = []
        pos = 0
        changes = 0
        text = self.text
        for m in pattern.finditer(text):
            r = repl(m) if callable(repl) else repl
            if r == m.group(0):
                continue
            changes += 1
            out.append(text[pos:m.start()])
            idx.extend(range(pos, m.start()))
            out.append(r)
            last = max(m.end() - 1, m.start())
            idx.extend(min(m.start() + i, last) for i in range(len(r)))
            pos = m.end()
        if not changes:
            return 0
        out.append(text[pos:])
        idx.extend(range(pos, len(text)))
        self.text = "".join(out)
        self.map = idx if self.map is None else [self.map[i] for i in idx]
        return changes

    def orig_pos(self, i: int) -> int:
        if self.map is None:
            return i
        if not self.map:
            return 0
        return self.map[min(i, len(self.map) - 1)]

    def orig_span(self, start: int, end: int) -> str:
        if end <= start:
            return ""
        return self.original[self.orig_pos(start): self.orig_pos(end - 1) + 1]

    def orig_line(self, start: int, limit: int = 240) -> str:
        o = self.orig_pos(start)
        ls = self.original.rfind("\n", 0, o) + 1
        le = self.original.find("\n", o)
        if le == -1:
            le = len(self.original)
        line = " ".join(self.original[ls:le].split())
        return line if len(line) <= limit else line[:limit] + "…"


# --------------------------------------------------------------------------
# Рефанг
# --------------------------------------------------------------------------

_I = re.IGNORECASE
_INVISIBLE = re.compile("[­​‌‍⁠﻿]")
_REFANG_STEPS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[ \t]*[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}][ \t]*", _I), "."),
    (re.compile(r"[\[\(\{]\s*:\s*[\]\)\}]"), ":"),
    (re.compile(r"[\[\(\{]\s*://\s*[\]\)\}]"), "://"),
    (re.compile(r"[\[\(\{]\s*/\s*[\]\)\}]"), "/"),
    (re.compile(r"[ \t]*[\[\(\{]\s*(?:@|at)\s*[\]\)\}][ \t]*", _I), "@"),
    (re.compile(r"\b(?:h[x*]{2}p|hxp)(s?)(?=://)", _I), r"http\1"),
    (re.compile(r"\bfxp(?=://)", _I), "ftp"),
]
_DEFANG_MARK = re.compile(r"[\[\]{}]|\((?:\.|dot|at|@|:)\)|h[x*]{2}p|fxp", _I)


def refang(text: str) -> str:
    mt = MappedText(text)
    _refang(mt)
    return mt.text


def _refang(mt: MappedText) -> None:
    mt.sub(_INVISIBLE, "")
    for pattern, repl in _REFANG_STEPS:
        if "\\1" in repl:
            mt.sub(pattern, lambda m, r=repl: m.expand(r))
        else:
            mt.sub(pattern, repl)


def defang(value: str, ioc_type: str) -> str:
    if ioc_type == "hash":
        return value
    v = re.sub(r"^http", "hxxp", value, flags=_I)
    v = re.sub(r"^ftp", "fxp", v, flags=_I)
    v = v.replace("://", "[:]//")
    if ioc_type == "url":
        # обезвреживаем только хост, путь оставляем как есть
        m = re.match(r"([^/]*//)([^/?#]*)(.*)", v, re.S)
        if m:
            return m.group(1) + m.group(2).replace(".", "[.]") + m.group(3)
    return v.replace(".", "[.]").replace("@", "[@]")


# --------------------------------------------------------------------------
# Склейка IoC, разорванных переносом строки
# --------------------------------------------------------------------------

_ASCII_TOKEN = re.compile(r"[\x21-\x7e]+\Z")
_SCHEME_START = re.compile(r"(?:https?|ftp)://", _I)
_NEW_IOC_START = re.compile(
    r"(?:[a-z]+://|\d{1,3}(?:\.\d{1,3}){3}|[\w-]+\.[\w-]|[^\s@]+@|(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b)", _I)

# Правая часть — в lookahead, чтобы не «съедать» токен следующей строки
# (он может сам оказаться началом очередного переноса).
_HASH_WRAP = re.compile(r"(?<![\w./:-])([0-9A-Fa-f]{8,127})[ \t]*\r?\n[ \t]*(?=([0-9A-Fa-f]{1,120})(?!\w))")
_HYPHEN_WRAP = re.compile(r"(\S*[A-Za-z0-9])([ \t]?)-[ \t]*\r?\n[ \t]*(?=([A-Za-z0-9]\S*))")
_URL_WRAP = re.compile(r"((?:https?|ftp)://\S+)[ \t]*\r?\n[ \t]*(?=(\S+))", _I)


def _join_hash(m: re.Match) -> str:
    a, b = m.group(1), m.group(2)
    if len(a) not in HASH_TYPES and len(a) + len(b) in HASH_TYPES:
        return a
    return m.group(0)


def _join_hyphen(m: re.Match) -> str:
    left, space, right = m.group(1), m.group(2), m.group(3)
    if not (_ASCII_TOKEN.match(left) and _ASCII_TOKEN.match(right)):
        return m.group(0)
    if _SCHEME_START.match(right) or not re.search(r"[./]", left + right):
        return m.group(0)
    # «example.com -» с пробелом перед дефисом — скорее тире, а не перенос
    if space and "." in left:
        return m.group(0)
    return f"{left}-"


def _join_url(m: re.Match) -> str:
    url, nxt = m.group(1), m.group(2)
    if url[-1] in ";,)]}>\"'" or not _ASCII_TOKEN.match(nxt):
        return m.group(0)
    if _NEW_IOC_START.match(nxt):
        return m.group(0)
    if url.endswith("."):
        ok = re.fullmatch(r"[a-z0-9]{1,6}[.;,]?", nxt) is not None
    else:
        ok = re.search(r"[^A-Za-z]", nxt) is not None
    return url if ok else m.group(0)


def _join_wrapped(mt: MappedText) -> None:
    for _ in range(3):
        n = mt.sub(_HASH_WRAP, _join_hash)
        n += mt.sub(_HYPHEN_WRAP, _join_hyphen)
        n += mt.sub(_URL_WRAP, _join_url)
        if not n:
            break


# --------------------------------------------------------------------------
# Регулярные выражения IoC (по рефангнутому тексту)
# --------------------------------------------------------------------------

_LABEL = r"[^\W_](?:[\w-]{0,61}[^\W_])?"
_DOMAIN_BODY = rf"(?:{_LABEL}\.)+[^\W\d_][\w-]{{0,62}}[^\W_]"

URL_RE = re.compile(r"\b(?:https?|ftp|sftp)://[^\s<>\"'«»`|\\^{}]+", _I)
EMAIL_RE = re.compile(rf"(?<![\w.+%-])[\w.+%-]{{1,64}}@{_DOMAIN_BODY}(?![\w-])", _I)
IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\w|\.\w)"
)
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?![\w:])", _I)
HASH_RE = re.compile(r"(?<!\w)(?:[0-9a-f]{128}|[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?!\w)", _I)
DOMAIN_RE = re.compile(rf"(?<![\w@.-]){_DOMAIN_BODY}(?![\w-]|\.\w)", _I)

_URL_TRAIL = ".,;:!?'\"»)]}>"


def _valid_tld(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in TLDS:
        return True
    try:
        return tld.encode("idna").decode("ascii") in TLDS
    except UnicodeError:
        return False


def _suspicious_plain_domain(domain: str) -> bool:
    """Отсев ложных срабатываний для НЕобезвреженных доменов."""
    labels = domain.split(".")
    tld, sld = labels[-1], labels[-2]
    if tld in FILE_EXT_TLDS:  # «script.py», «archive.zip»
        return True
    if all(lbl.isdigit() for lbl in labels[:-1]):  # «510,100.com» — сумма/имя файла
        return True
    if not domain.isascii():  # «г.Москва», «см.сайт» — сокращения в русском тексте
        return not (tld == "рф" and len(sld) >= 3)
    return False


def _clean_url(url: str) -> str:
    while url and url[-1] in _URL_TRAIL:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def _url_host(url: str) -> str:
    m = re.match(r"[a-z]+://(?:[^@/?#]*@)?(\[[^\]]+\]|[^:/?#]+)", url, _I)
    return m.group(1).strip("[]").lower() if m else ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_url(url: str) -> str:
    m = re.match(r"([a-z]+://)([^/?#]*)(.*)", url, _I | re.S)
    if not m:
        return url
    return m.group(1).lower() + m.group(2).lower() + m.group(3)


# --------------------------------------------------------------------------
# Исключения (белый список)
# --------------------------------------------------------------------------

class Exclusions:
    def __init__(self, items: Iterable[str]):
        self.domains: set[str] = set()
        self.networks: list[ipaddress._BaseNetwork] = []
        self.values: set[str] = set()
        for raw in items:
            item = raw.strip().lower()
            if not item or item.startswith("#"):
                continue
            item = refang(item)
            try:
                self.networks.append(ipaddress.ip_network(item, strict=False))
                continue
            except ValueError:
                pass
            if "/" in item or "@" in item or re.fullmatch(r"[0-9a-f]{32,128}", item):
                self.values.add(item)
            else:
                self.domains.add(item.lstrip("*."))

    def _domain_hit(self, domain: str) -> bool:
        parts = domain.lower().split(".")
        return any(".".join(parts[i:]) in self.domains for i in range(len(parts)))

    def _ip_hit(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(ip in net for net in self.networks if net.version == ip.version)

    def hit(self, ioc_type: str, value: str) -> bool:
        if value.lower() in self.values:
            return True
        if ioc_type == "domain":
            return self._domain_hit(value)
        if ioc_type == "ip":
            return self._ip_hit(value)
        if ioc_type == "email":
            return self._domain_hit(value.rsplit("@", 1)[-1])
        if ioc_type == "url":
            host = _url_host(value)
            return self._ip_hit(host) if _is_ip(host) else self._domain_hit(host)
        return False


# --------------------------------------------------------------------------
# Основная функция
# --------------------------------------------------------------------------

def _mask(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    chars = list(text)
    for s, e in spans:
        chars[s:e] = " " * (e - s)
    return "".join(chars)


def extract(text: str, options: Options | None = None, source: str = "",
            join_wrapped: bool | None = None) -> list[IoC]:
    """Извлекает IoC из текста. join_wrapped переопределяет options.join_wrapped."""
    opts = options or Options()
    excl = Exclusions(opts.exclusions)
    mt = MappedText(text)
    _refang(mt)
    if opts.join_wrapped if join_wrapped is None else join_wrapped:
        _join_wrapped(mt)

    found: dict[tuple[str, str], IoC] = {}
    work = mt.text

    def add(ioc_type: str, value: str, subtype: str, start: int, end: int) -> None:
        if ioc_type not in opts.types:
            return
        is_defanged = bool(_DEFANG_MARK.search(mt.orig_span(start, end)))
        if opts.defanged_only and ioc_type != "hash" and not is_defanged:
            return
        if excl.hit(ioc_type, value):
            return
        key = (ioc_type, value)
        if key in found:
            found[key].count += 1
            found[key].defanged |= is_defanged
            return
        found[key] = IoC(ioc_type, value, subtype, is_defanged, 1,
                         [source] if source else [], mt.orig_line(start))

    def add_ip(value: str, start: int, end: int) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        if opts.skip_private_ip and (ip.is_private or ip.is_loopback or ip.is_unspecified
                                     or ip.is_multicast or ip.is_reserved or ip.is_link_local):
            return True
        add("ip", str(ip), f"ipv{ip.version}", start, end)
        return True

    # URL
    spans: list[tuple[int, int]] = []
    for m in URL_RE.finditer(work):
        url = _clean_url(m.group(0))
        host = _url_host(url)
        if not host or not (_is_ip(host) or ("." in host and _valid_tld(host))):
            continue
        s, e = m.start(), m.start() + len(url)
        spans.append((s, e))
        add("url", _normalize_url(url), "", s, e)
        if opts.include_url_hosts:
            if _is_ip(host):
                add_ip(host, s, e)
            else:
                add("domain", host, "", s, e)
    work = _mask(work, spans)

    # Email
    spans = []
    for m in EMAIL_RE.finditer(work):
        value = m.group(0).strip(".")
        local, _, domain = value.rpartition("@")
        if not local or not _valid_tld(domain):
            continue
        spans.append(m.span())
        add("email", f"{local}@{domain.lower()}", "", *m.span())
    work = _mask(work, spans)

    # Хэши
    spans = []
    for m in HASH_RE.finditer(work):
        value = m.group(0).lower()
        if value.isdigit() or len(set(value)) < 4:
            continue
        spans.append(m.span())
        add("hash", value, HASH_TYPES[len(value)], *m.span())
    work = _mask(work, spans)

    # IP
    spans = []
    for m in IPV4_RE.finditer(work):
        if add_ip(m.group(0), *m.span()):
            spans.append(m.span())
    for m in IPV6_RE.finditer(work):
        cand = m.group(0)
        if cand.count(":") >= 2 and len(cand) >= 6 and add_ip(cand, *m.span()):
            spans.append(m.span())
    work = _mask(work, spans)

    # Домены
    for m in DOMAIN_RE.finditer(work):
        value = m.group(0).lower()
        if not _valid_tld(value):
            continue
        if not _DEFANG_MARK.search(mt.orig_span(*m.span())) and _suspicious_plain_domain(value):
            continue
        add("domain", value, "", *m.span())

    order = {t: i for i, t in enumerate(IOC_TYPES)}
    return sorted(found.values(), key=lambda i: (order[i.type], i.subtype, i.value))


def merge(groups: Iterable[Iterable[IoC]]) -> list[IoC]:
    """Объединяет результаты по нескольким документам."""
    result: dict[tuple[str, str], IoC] = {}
    for group in groups:
        for ioc in group:
            cur = result.get(ioc.key)
            if cur is None:
                result[ioc.key] = IoC(ioc.type, ioc.value, ioc.subtype, ioc.defanged,
                                      ioc.count, list(ioc.sources), ioc.context)
                continue
            cur.count += ioc.count
            cur.defanged |= ioc.defanged
            cur.sources.extend(s for s in ioc.sources if s not in cur.sources)
    order = {t: i for i, t in enumerate(IOC_TYPES)}
    return sorted(result.values(), key=lambda i: (order[i.type], i.subtype, i.value))
