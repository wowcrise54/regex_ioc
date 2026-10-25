"""Графический интерфейс (Tkinter)."""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .exporters import export_csv, export_per_type, export_txt
from .extractor import DEFAULT_EXCLUSIONS, IOC_TYPES, TYPE_TITLES, IoC, Options, extract, merge
from .opencti import OpenCTIClient, OpenCTIError
from .readers import JOINABLE_KINDS, SUPPORTED_EXTENSIONS, Document, ReadError, read_document

APP_NAME = "IoC Extractor"
SETTINGS_PATH = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "IoCExtractor", "settings.json")

DEFAULT_SETTINGS = {
    "types": list(IOC_TYPES),
    "join_wrapped": True,
    "defanged_only": False,
    "include_url_hosts": False,
    "skip_private_ip": True,
    "export_defanged": False,
    "exclusions": list(DEFAULT_EXCLUSIONS),
    "opencti_url": "",
    "opencti_token": "",
    "remember_token": False,
    "verify_ssl": True,
    "score": 50,
    "create_indicator": True,
    "create_report": True,
    "last_dir": "",
}

COLUMNS = (
    ("type", "Тип", 70),
    ("subtype", "Подтип", 70),
    ("value", "Значение", 420),
    ("defanged", "Defanged", 70),
    ("count", "Кол-во", 60),
    ("sources", "Источник", 160),
    ("context", "Контекст", 400),
)


def load_settings() -> dict:
    settings = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            settings.update(json.load(f))
    except (OSError, ValueError):
        pass
    return settings


def save_settings(settings: dict) -> None:
    data = dict(settings)
    if not data.get("remember_token"):
        data["opencti_token"] = ""
    try:
        os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


class App(tk.Tk):
    def __init__(self, files: list[str] | None = None):
        super().__init__()
        self.title(f"{APP_NAME} {__version__}")
        self.geometry("1200x720")
        self.minsize(900, 500)
        self.settings = load_settings()
        self.documents: list[Document] = []
        self.removed: set[tuple[str, str]] = set()
        self.iocs: list[IoC] = []
        self.rows: dict[str, IoC] = {}
        self.sort_col, self.sort_reverse = "", False
        self.paste_counter = 0
        self._queue: queue.Queue = queue.Queue()

        self._build_vars()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_queue)
        if files:
            self.after(200, lambda: self.load_files(files))

    # ------------------------------------------------------------------ UI
    def _build_vars(self) -> None:
        s = self.settings
        self.type_vars = {t: tk.BooleanVar(value=t in s["types"]) for t in IOC_TYPES}
        self.join_var = tk.BooleanVar(value=s["join_wrapped"])
        self.defanged_only_var = tk.BooleanVar(value=s["defanged_only"])
        self.url_hosts_var = tk.BooleanVar(value=s["include_url_hosts"])
        self.private_ip_var = tk.BooleanVar(value=s["skip_private_ip"])
        self.export_defanged_var = tk.BooleanVar(value=s["export_defanged"])
        self.filter_type_var = tk.StringVar(value="Все")
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Откройте документ (PDF, DOCX, CSV, TXT) или вставьте текст")
        self.docs_var = tk.StringVar(value="Документы не загружены")

    def _build_ui(self) -> None:
        pad = {"padx": 6, "pady": 4}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)
        ttk.Button(top, text="Открыть файлы…", command=self.open_files).pack(side="left")
        ttk.Button(top, text="Вставить текст…", command=self.paste_text).pack(side="left", padx=4)
        ttk.Button(top, text="Очистить", command=self.clear).pack(side="left")
        ttk.Label(top, textvariable=self.docs_var, foreground="#555").pack(side="left", padx=12)
        ttk.Button(top, text="Исключения…", command=self.edit_exclusions).pack(side="right")

        opts = ttk.LabelFrame(self, text="Параметры извлечения")
        opts.pack(fill="x", **pad)
        row1 = ttk.Frame(opts)
        row1.pack(fill="x", padx=6, pady=2)
        ttk.Label(row1, text="Типы:").pack(side="left")
        for t in IOC_TYPES:
            ttk.Checkbutton(row1, text=TYPE_TITLES[t], variable=self.type_vars[t],
                            command=self.recompute).pack(side="left", padx=4)
        for pair in (
            (("Склеивать IoC, разорванные переносом строки (PDF/TXT)", self.join_var),
             ("Только обезвреженные (hxxp, [.])", self.defanged_only_var)),
            (("Добавлять домены/IP из URL", self.url_hosts_var),
             ("Пропускать частные/служебные IP", self.private_ip_var)),
        ):
            row = ttk.Frame(opts)
            row.pack(fill="x", padx=6, pady=2)
            for text, var in pair:
                ttk.Checkbutton(row, text=text, variable=var, command=self.recompute).pack(side="left", padx=4)

        flt = ttk.Frame(self)
        flt.pack(fill="x", **pad)
        ttk.Label(flt, text="Показать:").pack(side="left")
        cb = ttk.Combobox(flt, textvariable=self.filter_type_var, state="readonly", width=12,
                          values=["Все"] + [TYPE_TITLES[t] for t in IOC_TYPES])
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_table())
        ttk.Label(flt, text="Поиск:").pack(side="left", padx=(12, 0))
        search = ttk.Entry(flt, textvariable=self.search_var, width=30)
        search.pack(side="left", padx=4)
        self.search_var.trace_add("write", lambda *a: self.refresh_table())
        self.counts_var = tk.StringVar()
        ttk.Label(flt, textvariable=self.counts_var).pack(side="right")

        table = ttk.Frame(self)
        table.pack(fill="both", expand=True, **pad)
        self.tree = ttk.Treeview(table, columns=[c[0] for c in COLUMNS], show="headings", selectmode="extended")
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, stretch=key in ("value", "context"),
                             anchor="center" if key in ("count", "defanged") else "w")
        vsb = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)

        self.menu = tk.Menu(self, tearoff=False)
        self.menu.add_command(label="Копировать значения", command=self.copy_selected)
        self.menu.add_command(label="Подробнее…", command=self.show_details)
        self.menu.add_separator()
        self.menu.add_command(label="Удалить из списка", command=self.delete_selected)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Double-1>", lambda e: self.show_details())
        self.tree.bind("<Delete>", lambda e: self.delete_selected())
        self.tree.bind("<Control-c>", lambda e: self.copy_selected())
        self.tree.bind("<Control-a>", lambda e: self.tree.selection_set(self.tree.get_children()))

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", **pad)
        txt_btn = ttk.Menubutton(bottom, text="Экспорт TXT")
        txt_menu = tk.Menu(txt_btn, tearoff=False)
        txt_menu.add_command(label="Все IoC в один файл…", command=lambda: self.export("txt", False))
        txt_menu.add_command(label="Отдельный файл на каждый тип…", command=lambda: self.export("txt", True))
        txt_btn["menu"] = txt_menu
        txt_btn.pack(side="left")
        csv_btn = ttk.Menubutton(bottom, text="Экспорт CSV")
        csv_menu = tk.Menu(csv_btn, tearoff=False)
        csv_menu.add_command(label="Все IoC в один файл…", command=lambda: self.export("csv", False))
        csv_menu.add_command(label="Отдельный файл на каждый тип…", command=lambda: self.export("csv", True))
        csv_btn["menu"] = csv_menu
        csv_btn.pack(side="left", padx=4)
        ttk.Checkbutton(bottom, text="Экспортировать в обезвреженном виде (hxxp, [.])",
                        variable=self.export_defanged_var).pack(side="left", padx=8)
        ttk.Button(bottom, text="Импорт в OpenCTI (Draft)…", command=self.import_opencti).pack(side="right")

        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x", side="bottom")

    # ------------------------------------------------------------ загрузка
    def open_files(self) -> None:
        patterns = " ".join(f"*{e}" for e in SUPPORTED_EXTENSIONS)
        files = filedialog.askopenfilenames(
            parent=self, title="Выберите документы", initialdir=self.settings.get("last_dir") or None,
            filetypes=[("Документы", patterns), ("PDF", "*.pdf"), ("Word", "*.docx"),
                       ("CSV", "*.csv"), ("Текст", "*.txt"), ("Все файлы", "*.*")])
        if files:
            self.settings["last_dir"] = os.path.dirname(files[0])
            self.load_files(list(files))

    def load_files(self, files: list[str]) -> None:
        self.status_var.set(f"Чтение файлов: {len(files)}…")
        self.config(cursor="watch")

        def worker():
            docs, errors = [], []
            for path in files:
                try:
                    docs.append(read_document(path))
                except (ReadError, OSError) as e:
                    errors.append(f"{os.path.basename(path)}: {e}")
            self._queue.put(("loaded", docs, errors))

        threading.Thread(target=worker, daemon=True).start()

    def paste_text(self) -> None:
        win = tk.Toplevel(self)
        win.title("Вставить текст")
        win.geometry("700x450")
        win.transient(self)
        text = tk.Text(win, wrap="word", undo=True)
        text.pack(fill="both", expand=True, padx=6, pady=6)
        text.focus_set()

        def apply():
            content = text.get("1.0", "end-1c")
            if content.strip():
                self.paste_counter += 1
                self._add_documents([Document(f"Вставленный текст {self.paste_counter}", "txt", content)], [])
            win.destroy()

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(btns, text="Извлечь IoC", command=apply).pack(side="right")
        ttk.Button(btns, text="Отмена", command=win.destroy).pack(side="right", padx=4)

    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self._queue.get_nowait()
                if msg[0] == "loaded":
                    self.config(cursor="")
                    self._add_documents(msg[1], msg[2])
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _add_documents(self, docs: list[Document], errors: list[str]) -> None:
        known = {d.path for d in self.documents}
        self.documents.extend(d for d in docs if d.path not in known)
        names = [d.name for d in self.documents]
        if names:
            shown = ", ".join(names[:3]) + (f" и ещё {len(names) - 3}" if len(names) > 3 else "")
            self.docs_var.set(f"Документы ({len(names)}): {shown}")
        self.recompute()
        if errors:
            messagebox.showwarning(APP_NAME, "Не удалось прочитать:\n\n" + "\n".join(errors), parent=self)

    def clear(self) -> None:
        self.documents.clear()
        self.removed.clear()
        self.docs_var.set("Документы не загружены")
        self.recompute()

    # ----------------------------------------------------------- извлечение
    def options(self) -> Options:
        return Options(
            types=frozenset(t for t, v in self.type_vars.items() if v.get()),
            join_wrapped=self.join_var.get(),
            defanged_only=self.defanged_only_var.get(),
            include_url_hosts=self.url_hosts_var.get(),
            skip_private_ip=self.private_ip_var.get(),
            exclusions=tuple(self.settings["exclusions"]),
        )

    def recompute(self) -> None:
        opts = self.options()
        groups = [extract(d.text, opts, d.name, join_wrapped=opts.join_wrapped and d.kind in JOINABLE_KINDS)
                  for d in self.documents]
        self.iocs = [i for i in merge(groups) if i.key not in self.removed]
        self.refresh_table()

    def _visible_iocs(self) -> list[IoC]:
        title = self.filter_type_var.get()
        type_filter = next((t for t in IOC_TYPES if TYPE_TITLES[t] == title), None)
        needle = self.search_var.get().strip().lower()
        items = [i for i in self.iocs
                 if (type_filter is None or i.type == type_filter)
                 and (not needle or needle in i.value.lower() or needle in i.context.lower())]
        if self.sort_col:
            key = {
                "count": lambda i: i.count,
                "sources": lambda i: "; ".join(i.sources),
                "defanged": lambda i: i.defanged,
            }.get(self.sort_col, lambda i: str(getattr(i, self.sort_col)).lower())
            items.sort(key=key, reverse=self.sort_reverse)
        return items

    def refresh_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        for n, ioc in enumerate(self._visible_iocs()):
            iid = str(n)
            self.rows[iid] = ioc
            self.tree.insert("", "end", iid=iid, values=(
                TYPE_TITLES[ioc.type], ioc.subtype, ioc.value, "да" if ioc.defanged else "",
                ioc.count, "; ".join(ioc.sources), ioc.context))
        counts = {t: 0 for t in IOC_TYPES}
        for ioc in self.iocs:
            counts[ioc.type] += 1
        self.counts_var.set("   ".join(f"{TYPE_TITLES[t]}: {c}" for t, c in counts.items())
                            + f"   Всего: {len(self.iocs)}")
        if self.documents:
            self.status_var.set(f"Найдено IoC: {len(self.iocs)} (показано: {len(self.rows)})")

    def sort_by(self, col: str) -> None:
        self.sort_reverse = not self.sort_reverse if self.sort_col == col else False
        self.sort_col = col
        self.refresh_table()

    # ------------------------------------------------------- работа с таблицей
    def _selected(self) -> list[IoC]:
        return [self.rows[i] for i in self.tree.selection() if i in self.rows]

    def _on_right_click(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if row and row not in self.tree.selection():
            self.tree.selection_set(row)
        self.menu.tk_popup(event.x_root, event.y_root)

    def copy_selected(self) -> None:
        items = self._selected()
        if items:
            self.clipboard_clear()
            self.clipboard_append("\n".join(i.value for i in items))
            self.status_var.set(f"Скопировано: {len(items)}")

    def delete_selected(self) -> None:
        items = self._selected()
        if not items:
            return
        self.removed.update(i.key for i in items)
        self.iocs = [i for i in self.iocs if i.key not in self.removed]
        self.refresh_table()
        self.status_var.set(f"Удалено из списка: {len(items)}")

    def show_details(self) -> None:
        items = self._selected()
        if not items:
            return
        i = items[0]
        messagebox.showinfo(APP_NAME, (
            f"Тип: {TYPE_TITLES[i.type]} {i.subtype}\n\nЗначение:\n{i.value}\n\n"
            f"Встречается: {i.count} раз(а)\nИсточник: {'; '.join(i.sources)}\n\nКонтекст:\n{i.context}"),
            parent=self)

    # -------------------------------------------------------------- экспорт
    def _base_name(self) -> str:
        if len(self.documents) == 1:
            return os.path.splitext(self.documents[0].name)[0] + "_ioc"
        return "ioc_" + datetime.now().strftime("%Y%m%d_%H%M")

    def export(self, fmt: str, per_type: bool) -> None:
        if not self.iocs:
            messagebox.showinfo(APP_NAME, "Список IoC пуст", parent=self)
            return
        defanged = self.export_defanged_var.get()
        initial_dir = self.settings.get("last_dir") or None
        try:
            if per_type:
                directory = filedialog.askdirectory(parent=self, title="Папка для файлов", initialdir=initial_dir)
                if not directory:
                    return
                files = export_per_type(self.iocs, directory, self._base_name(), fmt, defanged)
                self.status_var.set(f"Экспортировано в {directory}: " + ", ".join(os.path.basename(f) for f in files))
            else:
                path = filedialog.asksaveasfilename(
                    parent=self, title="Сохранить как", initialdir=initial_dir,
                    initialfile=f"{self._base_name()}.{fmt}", defaultextension=f".{fmt}",
                    filetypes=[(fmt.upper(), f"*.{fmt}"), ("Все файлы", "*.*")])
                if not path:
                    return
                (export_csv if fmt == "csv" else export_txt)(self.iocs, path, defanged)
                self.status_var.set(f"Экспортировано {len(self.iocs)} IoC в {path}")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Ошибка записи файла:\n{e}", parent=self)

    # ----------------------------------------------------------- исключения
    def edit_exclusions(self) -> None:
        win = tk.Toplevel(self)
        win.title("Исключения (белый список)")
        win.geometry("520x420")
        win.transient(self)
        ttk.Label(win, justify="left", wraplength=500, text=(
            "По одному значению на строку. Домен исключается вместе с поддоменами "
            "(и URL/email на нём). Для IP можно указать подсеть: 10.0.0.0/8. "
            "Строки, начинающиеся с #, — комментарии.")).pack(fill="x", padx=6, pady=6)
        text = tk.Text(win, wrap="none")
        text.pack(fill="both", expand=True, padx=6)
        text.insert("1.0", "\n".join(self.settings["exclusions"]))

        def apply():
            self.settings["exclusions"] = [l.strip() for l in text.get("1.0", "end").splitlines() if l.strip()]
            save_settings(self.settings)
            win.destroy()
            self.recompute()

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=6, pady=6)
        ttk.Button(btns, text="Сохранить", command=apply).pack(side="right")
        ttk.Button(btns, text="По умолчанию", command=lambda: (
            text.delete("1.0", "end"), text.insert("1.0", "\n".join(DEFAULT_EXCLUSIONS)))).pack(side="right", padx=4)
        ttk.Button(btns, text="Отмена", command=win.destroy).pack(side="left")

    # -------------------------------------------------------------- OpenCTI
    def import_opencti(self) -> None:
        if not self.iocs:
            messagebox.showinfo(APP_NAME, "Список IoC пуст", parent=self)
            return
        OpenCTIDialog(self)

    def _on_close(self) -> None:
        s = self.settings
        s["types"] = [t for t, v in self.type_vars.items() if v.get()]
        s["join_wrapped"] = self.join_var.get()
        s["defanged_only"] = self.defanged_only_var.get()
        s["include_url_hosts"] = self.url_hosts_var.get()
        s["skip_private_ip"] = self.private_ip_var.get()
        s["export_defanged"] = self.export_defanged_var.get()
        save_settings(s)
        self.destroy()


class OpenCTIDialog(tk.Toplevel):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self.title("Импорт в OpenCTI (Draft)")
        self.geometry("620x600")
        self.transient(app)
        self.grab_set()
        s = app.settings
        self._queue: queue.Queue = queue.Queue()
        self._cancel = threading.Event()
        self._running = False

        self.url_var = tk.StringVar(value=s["opencti_url"])
        self.token_var = tk.StringVar(value=s["opencti_token"])
        self.remember_var = tk.BooleanVar(value=s["remember_token"])
        self.verify_var = tk.BooleanVar(value=s["verify_ssl"])
        doc = app.documents[0].name if len(app.documents) == 1 else f"{len(app.documents)} документов"
        self.name_var = tk.StringVar(value=f"IoC: {doc} — {datetime.now():%Y-%m-%d %H:%M}")
        self.score_var = tk.IntVar(value=s["score"])
        self.indicator_var = tk.BooleanVar(value=s["create_indicator"])
        self.report_var = tk.BooleanVar(value=s["create_report"])
        counts = {t: sum(1 for i in app.iocs if i.type == t) for t in IOC_TYPES}
        self.type_vars = {t: tk.BooleanVar(value=counts[t] > 0) for t in IOC_TYPES}

        frm = ttk.Frame(self, padding=8)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)
        r = 0
        ttk.Label(frm, text="URL OpenCTI:").grid(row=r, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.url_var).grid(row=r, column=1, columnspan=2, sticky="ew", pady=2)
        r += 1
        ttk.Label(frm, text="API-токен:").grid(row=r, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.token_var, show="•").grid(row=r, column=1, sticky="ew", pady=2)
        ttk.Button(frm, text="Проверить", command=self.check).grid(row=r, column=2, padx=(4, 0))
        r += 1
        line = ttk.Frame(frm)
        line.grid(row=r, column=1, columnspan=2, sticky="w")
        ttk.Checkbutton(line, text="Запомнить токен", variable=self.remember_var).pack(side="left")
        ttk.Checkbutton(line, text="Проверять SSL-сертификат", variable=self.verify_var).pack(side="left", padx=8)
        r += 1
        ttk.Separator(frm).grid(row=r, column=0, columnspan=3, sticky="ew", pady=6)
        r += 1
        ttk.Label(frm, text="Имя черновика:").grid(row=r, column=0, sticky="w", pady=2)
        ttk.Entry(frm, textvariable=self.name_var).grid(row=r, column=1, columnspan=2, sticky="ew", pady=2)
        r += 1
        ttk.Label(frm, text="Описание:").grid(row=r, column=0, sticky="nw", pady=2)
        self.desc = tk.Text(frm, height=3, wrap="word")
        self.desc.grid(row=r, column=1, columnspan=2, sticky="ew", pady=2)
        self.desc.insert("1.0", "Источник: " + "; ".join(d.name for d in app.documents))
        r += 1
        ttk.Label(frm, text="Score (0-100):").grid(row=r, column=0, sticky="w", pady=2)
        ttk.Spinbox(frm, from_=0, to=100, textvariable=self.score_var, width=6).grid(row=r, column=1, sticky="w")
        r += 1
        ttk.Checkbutton(frm, text="Создавать индикаторы (Indicator) для наблюдаемых",
                        variable=self.indicator_var).grid(row=r, column=1, columnspan=2, sticky="w")
        r += 1
        ttk.Checkbutton(frm, text="Создать отчёт (Report), содержащий все IoC",
                        variable=self.report_var).grid(row=r, column=1, columnspan=2, sticky="w")
        r += 1
        types = ttk.LabelFrame(frm, text="Что импортировать")
        types.grid(row=r, column=0, columnspan=3, sticky="ew", pady=6)
        for t in IOC_TYPES:
            ttk.Checkbutton(types, text=f"{TYPE_TITLES[t]} ({counts[t]})", variable=self.type_vars[t],
                            state="normal" if counts[t] else "disabled").pack(side="left", padx=6, pady=4)
        r += 1
        self.progress = ttk.Progressbar(frm, mode="determinate")
        self.progress.grid(row=r, column=0, columnspan=3, sticky="ew", pady=4)
        r += 1
        self.log = tk.Text(frm, height=8, wrap="word", state="disabled")
        self.log.grid(row=r, column=0, columnspan=3, sticky="nsew")
        frm.rowconfigure(r, weight=1)
        r += 1
        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        self.import_btn = ttk.Button(btns, text="Импортировать", command=self.start)
        self.import_btn.pack(side="right")
        ttk.Button(btns, text="Закрыть", command=self.close).pack(side="right", padx=4)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.after(100, self._poll)

    def _write(self, msg: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _client(self) -> OpenCTIClient | None:
        url, token = self.url_var.get().strip(), self.token_var.get().strip()
        if not url or not token:
            messagebox.showwarning(APP_NAME, "Укажите URL OpenCTI и API-токен", parent=self)
            return None
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_var.set(url)
        return OpenCTIClient(url, token, verify_ssl=self.verify_var.get())

    def _save(self) -> None:
        s = self.app.settings
        s.update(opencti_url=self.url_var.get().strip(), opencti_token=self.token_var.get().strip(),
                 remember_token=self.remember_var.get(), verify_ssl=self.verify_var.get(),
                 score=self.score_var.get(), create_indicator=self.indicator_var.get(),
                 create_report=self.report_var.get())
        save_settings(s)

    def check(self) -> None:
        client = self._client()
        if not client:
            return
        self._write("Проверка подключения…")

        def worker():
            try:
                self._queue.put(("log", f"Подключено. Версия OpenCTI: {client.version()}"))
            except OpenCTIError as e:
                self._queue.put(("log", f"Ошибка: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def start(self) -> None:
        if self._running:
            self._cancel.set()
            return
        client = self._client()
        if not client:
            return
        selected = {t for t, v in self.type_vars.items() if v.get()}
        iocs = [i for i in self.app.iocs if i.type in selected]
        if not iocs:
            messagebox.showinfo(APP_NAME, "Не выбрано ни одного IoC для импорта", parent=self)
            return
        try:
            score = max(0, min(100, int(self.score_var.get())))
        except (tk.TclError, ValueError):
            score = 50
        name = self.name_var.get().strip() or "IoC import"
        description = self.desc.get("1.0", "end").strip()
        create_indicator, create_report = self.indicator_var.get(), self.report_var.get()
        self._save()
        self._running = True
        self._cancel.clear()
        self.import_btn.configure(text="Остановить")
        self.progress.configure(maximum=len(iocs), value=0)
        self._write(f"Создание черновика «{name}» и импорт {len(iocs)} IoC…")

        def worker():
            try:
                result = client.import_iocs(
                    iocs, name, score, create_indicator, create_report, description,
                    progress=lambda n, total: self._queue.put(("progress", n)),
                    cancelled=self._cancel.is_set)
                self._queue.put(("done", result))
            except OpenCTIError as e:
                self._queue.put(("error", str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self._write(payload)
                elif kind == "progress":
                    self.progress.configure(value=payload)
                elif kind == "error":
                    self._finish()
                    self._write(f"Ошибка: {payload}")
                elif kind == "done":
                    self._finish()
                    self._report(payload)
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(100, self._poll)

    def _finish(self) -> None:
        self._running = False
        self.import_btn.configure(text="Импортировать")

    def _report(self, result) -> None:
        self._write(f"Готово. Черновик: «{result.draft_name}» (id {result.draft_id})")
        self._write(f"Создано наблюдаемых: {result.created}")
        if result.report_id:
            self._write("Отчёт (Report) с IoC создан в черновике")
        for err in result.errors[:50]:
            self._write(f"  ! {err}")
        if len(result.errors) > 50:
            self._write(f"  … и ещё ошибок: {len(result.errors) - 50}")
        self._write("Откройте черновик в OpenCTI: Data → Import → Drafts.")

    def close(self) -> None:
        if self._running:
            if not messagebox.askyesno(APP_NAME, "Импорт ещё идёт. Прервать?", parent=self):
                return
            self._cancel.set()
        self.grab_release()
        self.destroy()


def main() -> None:
    if sys.platform == "win32":
        try:  # чёткий шрифт на экранах с масштабированием
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    files = [a for a in sys.argv[1:] if os.path.isfile(a)]
    App(files).mainloop()
