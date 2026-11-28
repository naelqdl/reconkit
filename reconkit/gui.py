"""reconkit desktop window: edit the scope, set options, run the CLI and open the report."""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, font, messagebox, ttk

from .discover import DEFAULT_DOH_URL
from .ports import TOP_PORTS

HERE = Path(__file__).parent
EXIT_MEANING = {0: "Report written", 2: "Scope or input error, nothing sent", 3: "crt.sh unavailable, no report",
                130: "Interrupted"}
# colour only where it has a job: green = the run action and success, red = errors, blue = progress steps
PALETTES = {
    # night black, moon white, bioluminescent blue
    "dark": dict(bg="#07090E", surface="#0F141C", raised="#1A2230", hover="#253042", border="#5F7088", text="#E6EBF2",
                 muted="#9AA6B8", disabled="#5F6B7D", accent="#38C8F0", accent_hi="#6FD9F7", accent_down="#1FA8D4",
                 on_accent="#07090E", ok="#6FD9F7", error="#F87171", info="#9DB8D9"),
    "light": dict(bg="#F3F5F9", surface="#FFFFFF", raised="#E1E6EE", hover="#CDD5E1", border="#77859A", text="#07090E",
                  muted="#475467", disabled="#97A1B0", accent="#00739E", accent_hi="#005F84", accent_down="#004C6A",
                  on_accent="#FFFFFF", ok="#00739E", error="#B91C1C", info="#2F5683"),
}


def system_theme() -> str:
    """'light' when Windows apps are set to light mode, else 'dark' (also the default off Windows)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            return "light" if winreg.QueryValueEx(key, "AppsUseLightTheme")[0] else "dark"
    except (ImportError, OSError):
        return "dark"


def text_scale() -> float:
    """Windows Accessibility > Text size (100-225 %), which Tk does not apply by itself."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Accessibility") as key:
            return max(1.0, min(2.25, winreg.QueryValueEx(key, "TextScaleFactor")[0] / 100))
    except (ImportError, OSError):
        return 1.0


def theme(root: tk.Tk, name: str, scale: float = 1.0) -> dict:
    p = dict(PALETTES[name])
    ui, mono = font.nametofont("TkDefaultFont").actual("family"), font.nametofont("TkFixedFont").actual("family")
    size = round(10 * scale)
    p.update(ui=(ui, size), mono=(mono, size), heading=(ui, round(11 * scale), "bold"))
    for named in ("TkDefaultFont", "TkTextFont"):  # entries use TkTextFont, not the style font
        font.nametofont(named).configure(family=ui, size=size)
    root.configure(bg=p["bg"])
    s = ttk.Style(root)
    s.theme_use("clam")  # the native Windows theme ignores widget colours
    s.configure(".", background=p["bg"], foreground=p["text"], fieldbackground=p["surface"], bordercolor=p["border"],
                lightcolor=p["border"], darkcolor=p["border"], troughcolor=p["bg"], focuscolor=p["bg"],
                insertcolor=p["text"], selectbackground=p["hover"], selectforeground=p["text"], font=p["ui"])
    s.configure("TEntry", padding=(6, 4))
    s.map("TEntry", bordercolor=[("focus", p["accent"])], lightcolor=[("focus", p["accent"])])
    s.configure("TButton", background=p["raised"], padding=(12, 6))
    s.map("TButton", background=[("disabled", p["bg"]), ("pressed", p["border"]), ("active", p["hover"])],
          foreground=[("disabled", p["disabled"])], bordercolor=[("focus", p["accent"])],
          lightcolor=[("focus", p["accent"])], darkcolor=[("focus", p["accent"])])
    s.configure("Run.TButton", background=p["accent"], foreground=p["on_accent"], bordercolor=p["accent"],
                font=(p["ui"][0], size, "bold"), padding=(18, 6))
    s.map("Run.TButton", background=[("disabled", p["raised"]), ("pressed", p["accent_down"]), ("active", p["accent_hi"])],
          foreground=[("disabled", p["disabled"])], bordercolor=[("disabled", p["border"]), ("focus", p["text"])])
    s.configure("TCheckbutton", padding=(0, 4), indicatorbackground=p["surface"], indicatorforeground=p["accent"],
                upperbordercolor=p["border"], lowerbordercolor=p["border"])
    s.map("TCheckbutton", background=[("active", p["bg"])], indicatorbackground=[("pressed", p["raised"])],
          upperbordercolor=[("focus", p["accent"])], lowerbordercolor=[("focus", p["accent"])])
    s.configure("Heading.TLabel", font=p["heading"])
    s.configure("Muted.TLabel", foreground=p["muted"])
    s.configure("Error.TLabel", foreground=p["error"])
    s.configure("Vertical.TScrollbar", background=p["raised"], troughcolor=p["surface"], arrowcolor=p["muted"],
                bordercolor=p["surface"])
    s.map("Vertical.TScrollbar", background=[("active", p["hover"])])
    try:  # title bar follows the theme on Windows 10 20H1+ / 11 (DWMWA_USE_IMMERSIVE_DARK_MODE)
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(name == "dark")), 4)
    except (AttributeError, OSError):
        pass
    try:
        if sys.platform == "win32":
            root.iconbitmap(default=str(HERE / "icon.ico"))  # default= also covers dialogs
        else:
            root.iconphoto(True, tk.PhotoImage(master=root, file=str(HERE / "icon.png")))
    except tk.TclError:
        pass  # a missing icon must not stop the app
    return p


def build_argv(domain: str, scope: str, out: str, concurrency: str, rate: str, timeout: str,
               doh_url: str, compare: str, active: bool = False) -> list[str]:
    """CLI arguments for one run; the CLI itself validates every value."""
    argv = [domain.strip(), "--scope", scope.strip(), "-o", out.strip() or "out",
            "--concurrency", concurrency.strip(), "--rate", rate.strip(), "--timeout", timeout.strip(),
            "--doh-url", doh_url.strip() or DEFAULT_DOH_URL]
    if compare.strip():
        argv += ["--compare", compare.strip()]
    if active:
        argv.append("--active")
    return argv


def cli_command(argv: list[str]) -> list[str]:
    if getattr(sys, "frozen", False):  # PyInstaller build: the app exe runs the CLI itself, see main()
        return [sys.executable, "--cli", *argv]
    return [sys.executable, "-u", "-m", "reconkit.cli", *argv]  # -u: progress lines arrive as printed


def elapsed(seconds: float) -> str:
    return f"{int(seconds) // 60}:{int(seconds) % 60:02d}"


class App:
    def __init__(self, root: tk.Tk, theme_name: str | None = None, scale: float | None = None):
        self.root, self.proc, self.lines, self.started, self.stopped = root, None, queue.Queue(), 0.0, False
        root.title("reconkit")
        scale = scale or text_scale()
        self.p = p = theme(root, theme_name or system_theme(), scale)
        outer = ttk.Frame(root)
        outer.pack(fill="both", expand=True)
        # the form scrolls only when the screen is too short for it (large text, small laptop screens)
        canvas = tk.Canvas(outer, bg=p["bg"], highlightthickness=0, borderwidth=0)
        vbar = ttk.Scrollbar(outer, command=canvas.yview)
        canvas.configure(yscrollcommand=vbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        f = ttk.Frame(canvas, padding=(24, 16, 24, 16))
        form = canvas.create_window(0, 0, window=f, anchor="nw")

        def fit(_=None):
            need, have = f.winfo_reqheight(), canvas.winfo_height()
            canvas.itemconfigure(form, width=canvas.winfo_width(), height=max(need, have))
            canvas.configure(scrollregion=(0, 0, 0, max(need, have)))
            if need > have and not vbar.winfo_ismapped():
                vbar.pack(side="right", fill="y", before=canvas)
            elif need <= have and vbar.winfo_ismapped():
                vbar.pack_forget()

        def wheel(e):  # text boxes scroll themselves
            if vbar.winfo_ismapped() and isinstance(e.widget, tk.Misc) and e.widget.winfo_class() != "Text":
                canvas.yview_scroll(-1 if e.num == 4 or getattr(e, "delta", 0) > 0 else 1, "units")

        def reveal(e):  # keyboard focus never lands on a control scrolled out of view
            w = e.widget
            if not vbar.winfo_ismapped() or not isinstance(w, tk.Misc) or w is canvas:
                return
            top, total = w.winfo_rooty() - f.winfo_rooty(), max(f.winfo_height(), 1)
            first, last = canvas.yview()
            if top < first * total or top + w.winfo_height() > last * total:
                canvas.yview_moveto(max(0, top - 24) / total)

        canvas.bind("<Configure>", fit)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            root.bind_all(seq, wheel)
        root.bind_all("<FocusIn>", reveal)
        f.columnconfigure(1, weight=1)
        self.v = {k: tk.StringVar(value=d) for k, d in [
            ("domain", ""), ("scope", "scope.txt"), ("out", "out"), ("concurrency", "10"), ("rate", "5"),
            ("timeout", "10"), ("doh_url", DEFAULT_DOH_URL), ("compare", "")]}
        self.v["active"] = tk.BooleanVar(value=False)
        box = dict(relief="flat", borderwidth=0, highlightthickness=1, highlightbackground=p["border"],
                   highlightcolor=p["accent"], padx=8, pady=6, bg=p["surface"], fg=p["text"], font=p["mono"],
                   insertbackground=p["text"], selectbackground=p["hover"], selectforeground=p["text"])

        # one left edge: labels in column 0, every field and the scope editor start at column 1
        def heading(r, text):
            ttk.Label(f, text=text, style="Heading.TLabel").grid(row=r, column=0, columnspan=3, sticky="w",
                                                                 pady=(0 if r == 0 else 24, 8))

        def label(r, text):
            ttk.Label(f, text=text).grid(row=r, column=0, sticky="w", padx=(0, 16), pady=4)

        def row(r, text, key, browse=None):
            label(r, text)
            entry = ttk.Entry(f, textvariable=self.v[key])
            entry.grid(row=r, column=1, columnspan=1 if browse else 2, sticky="ew", pady=4)
            if browse:
                ttk.Button(f, text="Browse...", command=browse).grid(row=r, column=2, padx=(8, 0), pady=4)
            return entry

        heading(0, "Target")
        self.domain_entry = row(1, "Domain", "domain")
        # the error line keeps its space while empty, so showing it never shifts the layout
        self.domain_error = ttk.Label(f, text="", style="Error.TLabel")
        self.domain_error.grid(row=2, column=1, columnspan=2, sticky="w")
        self.v["domain"].trace_add("write", lambda *_: self.domain_error.configure(text=""))
        row(3, "Scope file", "scope", lambda: self.pick("scope", filedialog.askopenfilename, load=True))
        self.scope_text = tk.Text(f, height=5, undo=True, **box)
        self.scope_text.grid(row=4, column=1, columnspan=2, sticky="ew", pady=(4, 8))
        self.scope_text.bind("<<Modified>>", lambda e: self.scope_hint.configure(
            text="Unsaved changes (Ctrl+S saves)" if self.scope_text.edit_modified() else self.SCOPE_HINT,
            foreground=p["text"] if self.scope_text.edit_modified() else p["muted"]))
        scope_bar = ttk.Frame(f)
        scope_bar.grid(row=5, column=1, columnspan=2, sticky="ew")
        self.scope_hint = ttk.Label(scope_bar, text=self.SCOPE_HINT, style="Muted.TLabel")
        self.scope_hint.pack(side="left")
        ttk.Button(scope_bar, text="Save", command=self.save_scope).pack(side="right")
        ttk.Button(scope_bar, text="Reload", command=self.load_scope).pack(side="right", padx=(0, 8))

        heading(6, "Scan options")
        label(7, "Limits")
        limits = ttk.Frame(f)
        limits.grid(row=7, column=1, columnspan=2, sticky="w", pady=4)
        for key, unit in [("concurrency", "at a time"), ("rate", "requests/s"), ("timeout", "s timeout")]:
            ttk.Entry(limits, textvariable=self.v[key], width=5, justify="right").pack(side="left")
            ttk.Label(limits, text=unit, style="Muted.TLabel").pack(side="left", padx=(8, 24))
        row(8, "DoH resolver", "doh_url")
        label(9, "Active checks")
        ttk.Checkbutton(f, variable=self.v["active"],
                        text=f"TCP connect to {len(TOP_PORTS)} common ports per host (more traffic than plain recon)"
                        ).grid(row=9, column=1, columnspan=2, sticky="w", pady=4)

        heading(10, "Report")
        row(11, "Output folder", "out", lambda: self.pick("out", filedialog.askdirectory))
        row(12, "Compare with", "compare", lambda: self.pick(
            "compare", lambda: filedialog.askopenfilename(filetypes=[("reconkit report", "report.json"), ("JSON", "*.json")])))

        bar = ttk.Frame(f)
        bar.grid(row=13, column=0, columnspan=3, sticky="ew", pady=(24, 8))
        self.run_btn = ttk.Button(bar, text="Run scan", command=self.run, style="Run.TButton", underline=0)
        self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.status = ttk.Label(bar, text="Ready", style="Muted.TLabel")
        self.status.pack(side="left", padx=8)
        self.report_btn = ttk.Button(bar, text="Open report", command=self.open_report, underline=0)
        self.report_btn.pack(side="right")

        log_box = ttk.Frame(f)
        log_box.grid(row=14, column=0, columnspan=3, sticky="nsew")
        log_box.columnconfigure(0, weight=1)
        log_box.rowconfigure(1, weight=1)
        self.log = tk.Text(log_box, height=8, state="disabled", wrap="word", **box)
        self.log.grid(row=0, column=0, sticky="nsew")
        bar_y = ttk.Scrollbar(log_box, command=self.log.yview)
        bar_y.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=bar_y.set)
        for tag, colour in [("cmd", p["muted"]), ("hint", p["muted"]), ("step", p["info"]), ("err", p["error"])]:
            self.log.tag_configure(tag, foreground=colour)
        self.log.tag_configure("hint", font=p["ui"])
        self.say("Scan output appears here.\nEnter a domain, check the scope above, then press Run scan (or Enter).\n", "hint")
        f.rowconfigure(14, weight=1)
        for text in (self.scope_text, self.log):  # Tab moves focus instead of being swallowed by the text box
            text.bind("<Tab>", lambda e: e.widget.tk_focusNext().focus_set() or "break")
            text.bind("<Shift-Tab>", lambda e: e.widget.tk_focusPrev().focus_set() or "break")
        ttk.Label(f, text="Only run reconkit against domains you own or are explicitly authorized to test.",
                  style="Muted.TLabel").grid(row=15, column=0, columnspan=3, sticky="w", pady=(8, 0))

        root.bind("<Return>", lambda e: self.run() if self.proc is None and e.widget is not self.scope_text else None)
        root.bind("<Escape>", lambda e: self.stop())
        root.bind("<Alt-r>", lambda e: self.run())
        root.bind("<Alt-o>", lambda e: self.open_report())
        root.bind("<Control-s>", lambda e: self.save_scope() and "break")
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.update_idletasks()
        # very large text on a short screen: step the text down until the form fits (the log may shrink to half)
        if scale > 1 and f.winfo_reqheight() - self.log.winfo_reqheight() // 2 > root.winfo_screenheight() - 120:
            outer.destroy()
            return self.__init__(root, theme_name, max(1.0, scale - 0.25))
        self.domain_entry.focus_set()
        # in pixels, so it follows display scaling; capped so large text still fits the screen
        w, h = min(f.winfo_reqwidth(), root.winfo_screenwidth() - 40), min(f.winfo_reqheight(), root.winfo_screenheight() - 120)
        root.minsize(w, h)
        root.geometry(f"{w}x{h}")
        if Path(self.v["scope"].get()).is_file():
            self.load_scope()
        root.after(100, self.drain)

    SCOPE_HINT = "One 'example.com' or '*.example.com' per line"

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
            return messagebox.showerror("reconkit", f"Can't read the scope file.\n\n{e}")
        self.scope_text.delete("1.0", "end")
        self.scope_text.insert("1.0", text)
        self.scope_text.edit_modified(False)

    def save_scope(self) -> bool:
        try:
            Path(self.v["scope"].get()).write_text(self.scope_text.get("1.0", "end-1c").rstrip() + "\n", encoding="utf-8")
        except OSError as e:
            messagebox.showerror("reconkit", f"Can't save the scope file. Pick another location with Browse.\n\n{e}")
            return False
        self.scope_text.edit_modified(False)
        return True

    def say(self, text: str, tag=None):
        self.log.configure(state="normal")
        if tag is None:
            tag = "cmd" if text.startswith("$ ") else "step" if text.startswith("[") else \
                "err" if text.startswith(("reconkit:", "Traceback", "error")) else ()
        self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_status(self, text: str, colour: str):
        self.status.configure(text=text, foreground=self.p[colour])

    def run(self):
        if self.proc is not None:
            return
        if not self.v["domain"].get().strip():
            self.domain_error.configure(text="Enter the domain to scan, for example example.com")
            return self.domain_entry.focus_set()
        if self.scope_text.edit_modified():
            answer = messagebox.askyesnocancel("reconkit", f"Save scope changes to {self.v['scope'].get()} first?")
            if answer is None or (answer and not self.save_scope()):
                return
        argv = build_argv(**{k: v.get() for k, v in self.v.items()})
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.say("$ reconkit " + subprocess.list2cmdline(argv) + "\n")
        self.proc = subprocess.Popen(cli_command(argv), stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        threading.Thread(target=self.pump, args=(self.proc,), daemon=True).start()
        self.started, self.stopped = time.monotonic(), False
        self.run_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.set_status("Running  0:00", "muted")

    def pump(self, proc):
        for line in proc.stdout:
            self.lines.put(line)
        self.lines.put(proc.wait())

    def drain(self):
        while not self.lines.empty():
            item = self.lines.get()
            if isinstance(item, int):
                self.finish(item)
            else:
                self.say(item)
        if self.proc is not None:
            self.set_status(f"Running  {elapsed(time.monotonic() - self.started)}", "muted")
        self.root.after(100, self.drain)

    def finish(self, code: int):
        self.proc = None
        self.run_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        took = elapsed(time.monotonic() - self.started)
        if self.stopped:
            return self.set_status(f"Stopped after {took}, no report", "muted")
        meaning = EXIT_MEANING.get(code, f"Failed (exit {code}), see the output")
        self.set_status(f"{meaning}  ·  {took}", "ok" if code == 0 else "error")
        if code == 0:
            self.report_btn.focus_set()

    def stop(self):
        if self.proc:
            self.stopped = True
            self.proc.terminate()

    def open_report(self):
        report = Path(self.v["out"].get() or "out") / "report.md"
        if not report.is_file():
            return messagebox.showinfo("reconkit", f"No report at {report.resolve()} yet. Run a scan first.")
        if hasattr(os, "startfile"):
            try:
                return os.startfile(report)
            except OSError:  # no app registered for .md
                pass
        webbrowser.open(report.resolve().as_uri())

    def close(self):
        if self.proc and not messagebox.askokcancel("reconkit", "A scan is running. Stop it and quit?"):
            return
        self.stop()
        self.root.destroy()


def main():
    if sys.argv[1:2] == ["--cli"]:  # frozen app re-launched by cli_command() to run one scan
        sys.stdout.reconfigure(line_buffering=True)
        try:
            from .cli import main as cli_main
            code = cli_main(sys.argv[2:])
        except Exception:  # print to the GUI log; uncaught, a windowed build shows a blocking error dialog
            import traceback
            traceback.print_exc(file=sys.stdout)
            code = 1
        raise SystemExit(code)
    try:  # own taskbar entry and icon on Windows, instead of grouping under python.exe
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("reconkit.gui")
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
