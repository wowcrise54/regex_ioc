"""Экспорт IoC в TXT и CSV — одним файлом или отдельным файлом на каждый тип."""

from __future__ import annotations

import csv
import os
from typing import Iterable

from .extractor import IOC_TYPES, TYPE_TITLES, IoC, defang

CSV_FIELDS = ("type", "subtype", "value", "value_defanged", "count", "sources", "context")


def _value(ioc: IoC, defanged: bool) -> str:
    return defang(ioc.value, ioc.type) if defanged else ioc.value


def _by_type(iocs: Iterable[IoC]) -> dict[str, list[IoC]]:
    groups: dict[str, list[IoC]] = {t: [] for t in IOC_TYPES}
    for ioc in iocs:
        groups[ioc.type].append(ioc)
    return {t: items for t, items in groups.items() if items}


def export_txt(iocs: list[IoC], path: str, defanged: bool = False) -> None:
    """Все IoC в одном файле, сгруппированные по типам."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        first = True
        for ioc_type, items in _by_type(iocs).items():
            if not first:
                f.write("\n")
            first = False
            f.write(f"# {TYPE_TITLES[ioc_type]} ({len(items)})\n")
            for ioc in items:
                f.write(_value(ioc, defanged) + "\n")


def export_csv(iocs: list[IoC], path: str, defanged: bool = False, delimiter: str = ";") -> None:
    # utf-8-sig + «;» — чтобы файл корректно открывался в русской локали Excel
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=delimiter)
        w.writerow(CSV_FIELDS)
        for ioc in iocs:
            w.writerow([ioc.type, ioc.subtype, _value(ioc, defanged), defang(ioc.value, ioc.type),
                        ioc.count, "; ".join(ioc.sources), ioc.context])


def export_per_type(iocs: list[IoC], directory: str, base: str, fmt: str,
                    defanged: bool = False) -> list[str]:
    """Отдельный файл на каждый тип IoC. Для TXT — только значения, по одному на строку."""
    written = []
    for ioc_type, items in _by_type(iocs).items():
        path = os.path.join(directory, f"{base}_{ioc_type}.{fmt}")
        if fmt == "csv":
            export_csv(items, path, defanged)
        else:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.writelines(_value(i, defanged) + "\n" for i in items)
        written.append(path)
    return written
