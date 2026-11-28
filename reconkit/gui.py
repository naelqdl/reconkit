"""reconkit desktop window: edit the scope, set options, run the CLI and open the report."""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .discover import DEFAULT_DOH_URL

EXIT_MEANING = {0: "report written", 2: "scope or input error, nothing sent", 3: "crt.sh unavailable, no report",
                130: "interrupted"}
# dark slate palette, colour only where it has a job: green = the run action and success, red = errors
BG, SURFACE, RAISED, BORDER = "#0F172A", "#1B2336", "#273449", "#475569"
TEXT, MUTED, DISABLED = "#E2E8F0", "#94A3B8", "#64748B"
ACCENT, ACCENT_HI, ACCENT_DOWN, ON_ACCENT = "#22C55E", "#4ADE80", "#16A34A", "#0F172A"
OK, ERROR, INFO = "#4ADE80", "#F87171", "#7DD3FC"
BOX = dict(relief="flat", borderwidth=0, highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT,
           padx=8, pady=6, bg=SURFACE, fg=TEXT, insertbackground=TEXT, selectbackground=BORDER,
           selectforeground=TEXT)


def theme(root: tk.Tk):
    root.configure(bg=BG)
    s = ttk.Style(root)
    s.theme_use("clam")  # the native Windows theme ignores widget colours
    s.configure(".", background=BG, foreground=TEXT, fieldbackground=SURFACE, bordercolor=BORDER,
                lightcolor=BORDER, darkcolor=BORDER, troughcolor=BG, focuscolor=BG, insertcolor=TEXT,
                selectbackground=BORDER, selectforeground=TEXT, font=("Segoe UI", 10))
    s.configure("TEntry", padding=(6, 4))
    s.map("TEntry", bordercolor=[("focus", ACCENT)], lightcolor=[("focus", ACCENT)])
    s.configure("TButton", background=RAISED, padding=(12, 4))
    s.map("TButton", background=[("disabled", BG), ("pressed", BORDER), ("active", "#334155")],
          foreground=[("disabled", DISABLED)], bordercolor=[("focus", ACCENT)])
    s.configure("Run.TButton", background=ACCENT, foreground=ON_ACCENT, bordercolor=ACCENT,
                font=("Segoe UI", 10, "bold"), padding=(18, 5))
    s.map("Run.TButton", background=[("disabled", RAISED), ("pressed", ACCENT_DOWN), ("active", ACCENT_HI)],
          foreground=[("disabled", DISABLED)], bordercolor=[("disabled", BORDER), ("focus", TEXT)])
    s.configure("Heading.TLabel", font=("Segoe UI", 11, "bold"))
    s.configure("Muted.TLabel", foreground=MUTED)
    s.configure("Vertical.TScrollbar", background=RAISED, troughcolor=SURFACE, arrowcolor=MUTED, bordercolor=SURFACE)
    s.map("Vertical.TScrollbar", background=[("active", BORDER)])
    try:  # dark title bar on Windows 10 20H1+ / 11 (DWMWA_USE_IMMERSIVE_DARK_MODE)
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(1)), 4)
    except (AttributeError, OSError):
        pass


def build_argv(domain: str, scope: str, out: str, concurrency: str, rate: str, timeout: str,
               doh_url: str, compare: str) -> list[str]:
    """CLI arguments for one run; the CLI itself validates every value."""
    argv = [domain.strip(), "--scope", scope.strip(), "-o", out.strip() or "out",
            "--concurrency", concurrency.strip(), "--rate", rate.strip(), "--timeout", timeout.strip(),
            "--doh-url", doh_url.strip() or DEFAULT_DOH_URL]
    if compare.strip():
        argv += ["--compare", compare.strip()]
    return argv


class App:
    def __init__(self, root: tk.Tk):
        self.root, self.proc, self.lines = root, None, queue.Queue()
        root.title("reconkit")
        root.minsize(760, 640)
        theme(root)
        f = ttk.Frame(root, padding=(16, 12, 16, 16))
        f.pack(fill="both", expand=True)
        f.columnconfigure(1, weight=1)
        self.v = {k: tk.StringVar(value=d) for k, d in [
            ("domain", ""), ("scope", "scope.txt"), ("out", "out"), ("concurrency", "10"), ("rate", "5"),
            ("timeout", "10"), ("doh_url", DEFAULT_DOH_URL), ("compare", "")]}

        # one left edge: labels in column 0, every field and the scope editor start at column 1
        def heading(r, text):
            ttk.Label(f, text=text, style="Heading.TLabel").grid(row=r, column=0, columnspan=3, sticky="w",
                                                                 pady=(0 if r == 0 else 16, 4))

        def row(r, label, key, browse=None):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", padx=(0, 12), pady=3)
            ttk.Entry(f, textvariable=self.v[key]).grid(row=r, column=1, columnspan=1 if browse else 2, sticky="ew", pady=3)
            if browse:
                ttk.Button(f, text="Browse...", command=browse).grid(row=r, column=2, padx=(8, 0), pady=3)

        heading(0, "Target")
        row(1, "Domain", "domain")
        row(2, "Scope file", "scope", lambda: self.pick("scope", filedialog.askopenfilename, load=True))
        self.scope_text = tk.Text(f, height=5, undo=True, font=("Consolas", 10), **BOX)
        self.scope_text.grid(row=3, column=1, columnspan=2, sticky="ew", pady=(3, 4))
        scope_bar = ttk.Frame(f)
        scope_bar.grid(row=4, column=1, columnspan=2, sticky="ew")
        ttk.Label(scope_bar, text="One 'example.com' or '*.example.com' per line", style="Muted.TLabel").pack(side="left")
        ttk.Button(scope_bar, text="Save", command=self.save_scope).pack(side="right")
        ttk.Button(scope_bar, text="Reload", command=self.load_scope).pack(side="right", padx=(0, 8))

        heading(5, "Options")
        opts = ttk.Frame(f)
        opts.grid(row=6, column=0, columnspan=3, sticky="w", pady=3)
        for label, key in [("Concurrency", "concurrency"), ("Rate (req/s)", "rate"), ("Timeout (s)", "timeout")]:
            ttk.Label(opts, text=label).pack(side="left")
            ttk.Entry(opts, textvariable=self.v[key], width=6, justify="right").pack(side="left", padx=(6, 20))
        row(7, "DoH URL", "doh_url")
        row(8, "Compare with", "compare", lambda: self.pick("compare", filedialog.askopenfilename))
        row(9, "Output dir", "out", lambda: self.pick("out", filedialog.askdirectory))

        bar = ttk.Frame(f)
        bar.grid(row=10, column=0, columnspan=3, sticky="ew", pady=(20, 8))
        self.run_btn = ttk.Button(bar, text="Run scan", command=self.run, style="Run.TButton", default="active")
        self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.status = ttk.Label(bar, text="Ready", style="Muted.TLabel")
        self.status.pack(side="left", padx=8)
        ttk.Button(bar, text="Open report", command=self.open_report).pack(side="right")

        log_box = ttk.Frame(f)
        log_box.grid(row=11, column=0, columnspan=3, sticky="nsew")
        log_box.columnconfigure(0, weight=1)
        log_box.rowconfigure(0, weight=1)
        self.log = tk.Text(log_box, height=12, state="disabled", font=("Consolas", 10), **BOX)
        self.log.grid(row=0, column=0, sticky="nsew")
        bar_y = ttk.Scrollbar(log_box, command=self.log.yview)
        bar_y.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=bar_y.set)
        for tag, colour in [("cmd", MUTED), ("step", INFO), ("err", ERROR)]:
            self.log.tag_configure(tag, foreground=colour)
        f.rowconfigure(11, weight=1)
        ttk.Label(f, text="Only run reconkit against domains you own or are explicitly authorized to test.",
                  style="Muted.TLabel").grid(row=12, column=0, columnspan=3, sticky="w", pady=(8, 0))
        root.bind("<Return>", lambda e: self.run() if self.proc is None and e.widget is not self.scope_text else None)
        root.protocol("WM_DELETE_WINDOW", self.close)
        if Path(self.v["scope"].get()).is_file():
            self.load_scope()
        root.after(100, self.drain)

    def pick(self, key, dialog, load=False):
        path = dialog()
        if path:
            self.v[key].set(path)
            if load:
                self.load_scope()

    def load_scope(self):
        try:
            text = Path(self.v["scope"].get()).read_text(encoding="utf-8")
        except OSError as e:
            return messagebox.showerror("reconkit", f"Can't read scope file: {e}")
        self.scope_text.delete("1.0", "end")
        self.scope_text.insert("1.0", text)
        self.scope_text.edit_modified(False)

    def save_scope(self) -> bool:
        try:
            Path(self.v["scope"].get()).write_text(self.scope_text.get("1.0", "end-1c").rstrip() + "\n", encoding="utf-8")
        except OSError as e:
            messagebox.showerror("reconkit", f"Can't save scope file: {e}")
            return False
        self.scope_text.edit_modified(False)
        return True

    def say(self, text: str):
        self.log.configure(state="normal")
        tag = "cmd" if text.startswith("$ ") else "step" if text.startswith("[") else \
            "err" if text.startswith(("reconkit:", "Traceback", "error")) else ()
        self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def run(self):
        if self.scope_text.edit_modified():
            answer = messagebox.askyesnocancel("reconkit", f"Save scope changes to {self.v['scope'].get()} first?")
            if answer is None or (answer and not self.save_scope()):
                return
        argv = build_argv(**{k: v.get() for k, v in self.v.items()})
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.say("$ reconkit " + subprocess.list2cmdline(argv) + "\n")
        # -u: unbuffered, so progress lines arrive as they're printed
        self.proc = subprocess.Popen([sys.executable, "-u", "-m", "reconkit.cli", *argv], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        threading.Thread(target=self.pump, args=(self.proc,), daemon=True).start()
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status.configure(text="Running ...", foreground=MUTED)

    def pump(self, proc):
        for line in proc.stdout:
            self.lines.put(line)
        self.lines.put(proc.wait())

    def drain(self):
        while not self.lines.empty():
            item = self.lines.get()
            if isinstance(item, int):
                self.proc = None
                self.run_btn.configure(state="normal")
                self.stop_btn.configure(state="disabled")
                self.status.configure(text=f"Exit {item}: {EXIT_MEANING.get(item, 'stopped')}", foreground=OK if item == 0 else ERROR)
            else:
                self.say(item)
        self.root.after(100, self.drain)

    def stop(self):
        if self.proc:
            self.proc.terminate()

    def open_report(self):
        report = Path(self.v["out"].get() or "out") / "report.md"
        if not report.is_file():
            return messagebox.showinfo("reconkit", f"No report at {report} yet.")
        if hasattr(os, "startfile"):
            os.startfile(report)
        else:
            webbrowser.open(report.resolve().as_uri())

    def close(self):
        self.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
