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
from tkinter.scrolledtext import ScrolledText

from .discover import DEFAULT_DOH_URL

EXIT_MEANING = {0: "report written", 2: "scope or input error, nothing sent", 3: "crt.sh unavailable, no report",
                130: "interrupted"}


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
        root.minsize(720, 560)
        f = ttk.Frame(root, padding=10)
        f.pack(fill="both", expand=True)
        f.columnconfigure(1, weight=1)
        self.v = {k: tk.StringVar(value=d) for k, d in [
            ("domain", ""), ("scope", "scope.txt"), ("out", "out"), ("concurrency", "10"), ("rate", "5"),
            ("timeout", "10"), ("doh_url", DEFAULT_DOH_URL), ("compare", "")]}

        def row(r, label, key, browse=None):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=2)
            ttk.Entry(f, textvariable=self.v[key]).grid(row=r, column=1, sticky="ew", pady=2)
            if browse:
                ttk.Button(f, text="Browse", command=browse).grid(row=r, column=2, padx=(6, 0))

        row(0, "Domain", "domain")
        row(1, "Scope file", "scope", lambda: self.pick("scope", filedialog.askopenfilename, load=True))
        scope_bar = ttk.Frame(f)
        scope_bar.grid(row=2, column=1, columnspan=2, sticky="w")
        ttk.Button(scope_bar, text="Load", command=self.load_scope).pack(side="left")
        ttk.Button(scope_bar, text="Save", command=self.save_scope).pack(side="left", padx=6)
        ttk.Label(scope_bar, text="one 'example.com' or '*.example.com' per line").pack(side="left")
        self.scope_text = tk.Text(f, height=5, undo=True)
        self.scope_text.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(2, 8))

        opts = ttk.Frame(f)
        opts.grid(row=4, column=0, columnspan=3, sticky="w")
        for label, key in [("Concurrency", "concurrency"), ("Rate (req/s)", "rate"), ("Timeout (s)", "timeout")]:
            ttk.Label(opts, text=label).pack(side="left")
            ttk.Entry(opts, textvariable=self.v[key], width=6).pack(side="left", padx=(4, 14))
        row(5, "DoH URL", "doh_url")
        row(6, "Compare with", "compare", lambda: self.pick("compare", filedialog.askopenfilename))
        row(7, "Output dir", "out", lambda: self.pick("out", filedialog.askdirectory))

        bar = ttk.Frame(f)
        bar.grid(row=8, column=0, columnspan=3, sticky="ew", pady=8)
        self.run_btn = ttk.Button(bar, text="Run", command=self.run)
        self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(bar, text="Open report", command=self.open_report).pack(side="left")
        self.status = ttk.Label(bar, text="Only run against domains you own or are authorized to test.")
        self.status.pack(side="left", padx=12)

        self.log = ScrolledText(f, height=14, state="disabled", font=("Consolas", 9))
        self.log.grid(row=9, column=0, columnspan=3, sticky="nsew")
        f.rowconfigure(9, weight=1)
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
        self.log.insert("end", text)
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
        self.status.configure(text="running ...")

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
                self.status.configure(text=f"exit {item}: {EXIT_MEANING.get(item, 'stopped')}")
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
