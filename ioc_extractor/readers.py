"""Чтение текста из документов: PDF, DOCX, CSV, TXT и прочих текстовых форматов."""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass
from xml.etree import ElementTree as ET

TEXT_EXTENSIONS = (".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".md", ".eml", ".ioc")
WORD_EXTENSIONS = (".docx", ".docm", ".dotx")
SUPPORTED_EXTENSIONS = (".pdf",) + WORD_EXTENSIONS + TEXT_EXTENSIONS

# Склейку разорванных переносом IoC имеет смысл делать только там, где перенос
# строки — артефакт вёрстки (PDF и текст, скопированный из PDF), а не граница записи.
JOINABLE_KINDS = ("pdf", "txt")


class ReadError(Exception):
    pass


@dataclass
class Document:
    path: str
    kind: str  # pdf | docx | csv | txt
    text: str

    @property
    def name(self) -> str:
        return os.path.basename(self.path)


def read_document(path: str) -> Document:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        return Document(path, "pdf", _read_pdf(path))
    if ext in WORD_EXTENSIONS:
        return Document(path, "docx", _read_docx(path))
    if ext == ".doc":
        raise ReadError("Формат .doc (Word 97-2003) не поддерживается — пересохраните файл как .docx")
    kind = "csv" if ext in (".csv", ".tsv") else "txt"
    return Document(path, kind, read_text_file(path))


def read_text_file(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
    return decode_bytes(data)


def decode_bytes(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    for enc in ("utf-8-sig", "cp1251"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def _read_pdf(path: str) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as e:  # pragma: no cover
        raise ReadError("Не установлен пакет pypdf") from e
    try:
        reader = PdfReader(path)
        if reader.is_encrypted:
            reader.decrypt("")
        pages = [page.extract_text() or "" for page in reader.pages]
    except Exception as e:
        raise ReadError(f"Не удалось прочитать PDF: {e}") from e
    text = "\n".join(pages)
    if not text.strip():
        raise ReadError("В PDF нет текстового слоя (вероятно, это скан) — нужен OCR")
    return text


_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_DOCX_PARTS = re.compile(r"word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$")


def _read_docx(path: str) -> str:
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            parts = sorted(n for n in names if _DOCX_PARTS.match(n))
            if "word/document.xml" in parts:  # основной текст — первым
                parts.remove("word/document.xml")
                parts.insert(0, "word/document.xml")
            chunks = [_docx_part_text(z.read(n)) for n in parts]
            # Внешние гиперссылки: адрес ссылки часто отличается от видимого текста
            links = []
            for n in names:
                if n.startswith("word/_rels/") and n.endswith(".rels"):
                    root = ET.fromstring(z.read(n))
                    for rel in root.iter(f"{_REL}Relationship"):
                        if rel.get("TargetMode") == "External" and rel.get("Type", "").endswith("/hyperlink"):
                            links.append(rel.get("Target", ""))
    except (zipfile.BadZipFile, KeyError, ET.ParseError) as e:
        raise ReadError(f"Не удалось прочитать DOCX: {e}") from e
    if links:
        chunks.append("\n".join(links))
    return "\n".join(chunks)


def _docx_part_text(xml: bytes) -> str:
    root = ET.fromstring(xml)
    lines = []
    for p in root.iter(f"{_W}p"):
        buf = []
        for el in p.iter():
            if el.tag == f"{_W}t" and el.text:
                buf.append(el.text)
            elif el.tag == f"{_W}tab":
                buf.append("\t")
            elif el.tag in (f"{_W}br", f"{_W}cr"):
                buf.append("\n")
        lines.append("".join(buf))
    return "\n".join(lines)
