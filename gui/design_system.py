"""Reusable UX primitives for the FileSentry Sentinel desktop console."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
import sys


DARK_COLORS = {
    "bg": "#06101D",
    "sidebar": "#091727",
    "panel": "#151D33",
    "panel_alt": "#0F1729",
    "panel_soft": "#101B30",
    "panel_elevated": "#1D3658",
    "border": "#264963",
    "border_soft": "#193650",
    "sidebar_active": "#102A45",
    "surface_hover": "#173653",
    "text": "#F8FAFC",
    "muted": "#A8B8CB",
    "subtle": "#6F849D",
    "cyan": "#36C5F0",
    "blue": "#60A5FA",
    "green": "#22C55E",
    "amber": "#F59E0B",
    "red": "#EF4444",
    "purple": "#A78BFA",
    "success_soft": "#103622",
    "warning_soft": "#3A2B0E",
    "danger_soft": "#3B161C",
    "info_soft": "#102D45",
}

LIGHT_COLORS = {
    "bg": "#F3F6FA",
    "sidebar": "#E7EEF6",
    "panel": "#FFFFFF",
    "panel_alt": "#EAF1F8",
    "panel_soft": "#EFF6FB",
    "panel_elevated": "#DCEAF6",
    "border": "#C7D6E5",
    "border_soft": "#D9E4EF",
    "sidebar_active": "#D6ECF7",
    "surface_hover": "#DCECF7",
    "text": "#102033",
    "muted": "#4F647A",
    "subtle": "#71859A",
    "cyan": "#087EA4",
    "blue": "#2563EB",
    "green": "#15803D",
    "amber": "#B45309",
    "red": "#C62828",
    "purple": "#7C3AED",
    "success_soft": "#E8F6ED",
    "warning_soft": "#FFF4DA",
    "danger_soft": "#FDEBEC",
    "info_soft": "#EAF5FC",
}


COLORS = dict(DARK_COLORS)


def detect_system_theme() -> str:
    """Return the Windows app theme, with a safe dark fallback."""
    if sys.platform != "win32":
        return "dark"
    try:
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return "light" if int(value) == 1 else "dark"
    except (OSError, ValueError, TypeError):
        return "dark"


def resolve_theme_mode(mode: str | None) -> str:
    """Resolve a stored mode (light/dark/system) to the active palette."""
    normalized = str(mode or "system").strip().lower()
    if normalized == "system":
        return detect_system_theme()
    return normalized if normalized in {"light", "dark"} else "dark"


def apply_theme_mode(mode: str | None) -> str:
    """Update the shared palette in place so imported COLORS references stay valid."""
    resolved = resolve_theme_mode(mode)
    COLORS.clear()
    COLORS.update(LIGHT_COLORS if resolved == "light" else DARK_COLORS)
    return resolved


def make_button(parent, text, command, *, bg=None, fg=None, width=None, small=False, outline=False):
    """Create a consistent, keyboard-friendly button with hover feedback."""
    normal_bg = bg or COLORS["panel_alt"]
    normal_fg = fg or COLORS["text"]
    hover_bg = COLORS["panel_elevated"] if outline else COLORS["cyan"]
    hover_fg = COLORS["text"] if outline else COLORS["bg"]
    button = tk.Button(
        parent,
        text=text,
        command=command,
        bg=normal_bg,
        fg=normal_fg,
        activebackground=hover_bg,
        activeforeground=hover_fg,
        relief="flat",
        bd=0,
        highlightthickness=1 if outline else 0,
        highlightbackground=COLORS["border"],
        highlightcolor=COLORS["cyan"],
        overrelief="flat",
        cursor="hand2",
        font=("Segoe UI", 8 if small else 9, "bold"),
        padx=13 if small else 15,
        pady=7 if small else 10,
    )
    if width:
        button.configure(width=width)

    def on_enter(_event):
        if str(button.cget("state")) != "disabled":
            button.configure(bg=hover_bg, fg=hover_fg)

    def on_leave(_event):
        if str(button.cget("state")) != "disabled":
            button.configure(bg=normal_bg, fg=normal_fg)

    button.bind("<Enter>", on_enter, add="+")
    button.bind("<Leave>", on_leave, add="+")
    return button


def configure_ttk_style(widget: tk.Misc) -> ttk.Style:
    style = ttk.Style(widget)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(
        "Treeview",
        background=COLORS["panel"],
        foreground=COLORS["text"],
        fieldbackground=COLORS["panel"],
        borderwidth=0,
        rowheight=34,
        font=("Segoe UI", 9),
    )
    style.configure(
        "Treeview.Heading",
        background=COLORS["panel_alt"],
        foreground=COLORS["muted"],
        relief="flat",
        padding=(10, 8),
        font=("Segoe UI", 8, "bold"),
    )
    style.map(
        "Treeview",
        background=[("selected", "#1D4ED8")],
        foreground=[("selected", "#FFFFFF")],
    )
    style.configure("TScrollbar", background=COLORS["panel_alt"], troughcolor=COLORS["bg"], arrowcolor=COLORS["muted"])
    return style


def status_pill(parent, text: str, color: str, *, compact: bool = False):
    frame = tk.Frame(parent, bg=color, padx=9 if compact else 12, pady=5 if compact else 7)
    tk.Label(
        frame,
        text=f"●  {text}",
        fg=COLORS["bg"],
        bg=color,
        font=("Segoe UI", 8 if compact else 9, "bold"),
    ).pack()
    return frame


class NoticeDialog(tk.Toplevel):
    """A polished, accessible replacement for native message boxes."""

    def __init__(self, parent, title: str, message: str, *, tone: str = "info", button_text: str = "ĐÓNG"):
        super().__init__(parent.winfo_toplevel() if hasattr(parent, "winfo_toplevel") else parent)
        self.title(title)
        self.configure(bg=COLORS["panel"])
        self.geometry("500x270")
        self.minsize(430, 220)
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel() if hasattr(parent, "winfo_toplevel") else parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        tone_color = {
            "success": COLORS["green"],
            "warning": COLORS["amber"],
            "error": COLORS["red"],
            "info": COLORS["cyan"],
        }.get(tone, COLORS["cyan"])
        tone_bg = {
            "success": COLORS["success_soft"],
            "warning": COLORS["warning_soft"],
            "error": COLORS["danger_soft"],
            "info": COLORS["info_soft"],
        }.get(tone, COLORS["info_soft"])
        header = tk.Frame(self, bg=tone_bg)
        header.pack(fill="x")
        tk.Frame(header, bg=tone_color, width=6).pack(side="left", fill="y")
        tk.Label(header, text={"success": "✓", "warning": "!", "error": "×", "info": "i"}.get(tone, "i"), fg=tone_color, bg=tone_bg, font=("Segoe UI", 22, "bold"), width=3).pack(side="left", padx=(16, 4), pady=15)
        tk.Label(header, text=title, fg=COLORS["text"], bg=tone_bg, font=("Segoe UI", 14, "bold"), anchor="w").pack(side="left", fill="x", expand=True, pady=17)
        body = tk.Frame(self, bg=COLORS["panel"])
        body.pack(fill="both", expand=True, padx=28, pady=(20, 12))
        tk.Label(body, text=message, fg=COLORS["muted"], bg=COLORS["panel"], justify="left", anchor="nw", wraplength=430, font=("Segoe UI", 10)).pack(fill="both", expand=True)
        make_button(self, button_text, self.destroy, bg=tone_color, fg=COLORS["bg"]).pack(anchor="e", padx=28, pady=(0, 20))
        self.bind("<Return>", lambda _event: self.destroy())
        self.bind("<Escape>", lambda _event: self.destroy())


class ConfirmDialog(tk.Toplevel):
    """Explicit confirmation dialog for destructive or policy-changing actions."""

    def __init__(self, parent, title: str, message: str, *, tone: str = "warning"):
        super().__init__(parent.winfo_toplevel() if hasattr(parent, "winfo_toplevel") else parent)
        self.result = False
        self.title(title)
        self.configure(bg=COLORS["panel"])
        self.geometry("520x285")
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel() if hasattr(parent, "winfo_toplevel") else parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.close)
        color = COLORS["red"] if tone == "danger" else COLORS["amber"]
        header = tk.Frame(self, bg=COLORS["panel_alt"])
        header.pack(fill="x")
        tk.Label(header, text="!", fg=color, bg=COLORS["panel_alt"], font=("Segoe UI", 22, "bold"), width=3).pack(side="left", padx=(20, 4), pady=15)
        tk.Label(header, text=title, fg=COLORS["text"], bg=COLORS["panel_alt"], font=("Segoe UI", 14, "bold")).pack(side="left", anchor="w")
        tk.Label(self, text=message, fg=COLORS["muted"], bg=COLORS["panel"], justify="left", anchor="nw", wraplength=455, font=("Segoe UI", 10)).pack(fill="both", expand=True, padx=28, pady=24)
        footer = tk.Frame(self, bg=COLORS["panel"])
        footer.pack(fill="x", padx=28, pady=(0, 20))
        make_button(footer, "HỦY", self.close, bg=COLORS["panel_alt"], fg=COLORS["muted"], outline=True).pack(side="right", padx=(8, 0))
        make_button(footer, "XÁC NHẬN", self.confirm, bg=color, fg=COLORS["bg"]).pack(side="right")
        self.bind("<Return>", lambda _event: self.confirm())
        self.bind("<Escape>", lambda _event: self.close())

    def confirm(self):
        self.result = True
        self.destroy()

    def close(self):
        self.result = False
        self.destroy()


class InputDialog(tk.Toplevel):
    """Consistent input dialog for origins, durations and confirmation text."""

    def __init__(self, parent, title: str, prompt: str, *, initialvalue: str = "", secret: bool = False, validator=None):
        super().__init__(parent.winfo_toplevel() if hasattr(parent, "winfo_toplevel") else parent)
        self.value = None
        self.validator = validator
        self.title(title)
        self.configure(bg=COLORS["panel"])
        self.geometry("500x245")
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel() if hasattr(parent, "winfo_toplevel") else parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.close)
        tk.Label(self, text=title, fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=28, pady=(24, 5))
        tk.Label(self, text=prompt, fg=COLORS["muted"], bg=COLORS["panel"], justify="left", anchor="w", wraplength=430, font=("Segoe UI", 9)).pack(fill="x", padx=28, pady=(0, 14))
        self.entry = tk.Entry(self, show="•" if secret else "", bg=COLORS["panel_alt"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", font=("Segoe UI", 11))
        self.entry.pack(fill="x", padx=28, ipady=8)
        self.error = tk.Label(self, text="", fg=COLORS["red"], bg=COLORS["panel"], font=("Segoe UI", 8))
        self.error.pack(anchor="w", padx=28, pady=(4, 0))
        footer = tk.Frame(self, bg=COLORS["panel"])
        footer.pack(fill="x", padx=28, pady=(10, 18))
        make_button(footer, "HỦY", self.close, bg=COLORS["panel_alt"], fg=COLORS["muted"], outline=True).pack(side="right", padx=(8, 0))
        make_button(footer, "TIẾP TỤC", self.submit, bg=COLORS["cyan"], fg=COLORS["bg"]).pack(side="right")
        self.entry.insert(0, initialvalue)
        self.entry.bind("<Return>", lambda _event: self.submit())
        self.bind("<Escape>", lambda _event: self.close())
        self.entry.focus_set()

    def submit(self):
        value = self.entry.get()
        if self.validator:
            try:
                value = self.validator(value)
            except (TypeError, ValueError) as exc:
                self.error.configure(text=str(exc))
                return
        self.value = value
        self.destroy()

    def close(self):
        self.value = None
        self.destroy()


class UXMessageBox:
    """Compatibility facade keeping existing call sites while upgrading UX."""

    @staticmethod
    def showinfo(title, message, parent=None, **_kwargs):
        if parent is not None and hasattr(parent, "toast"):
            parent.toast(title, message, "success")
            return "ok"
        dialog = NoticeDialog(parent, title, message, tone="success")
        dialog.wait_window()
        if parent is not None and hasattr(parent, "grab_set"):
            parent.grab_set()
        return "ok"

    @staticmethod
    def showerror(title, message, parent=None, **_kwargs):
        dialog = NoticeDialog(parent, title, message, tone="error", button_text="ĐÓNG")
        dialog.wait_window()
        if parent is not None and hasattr(parent, "grab_set"):
            parent.grab_set()
        return "ok"

    @staticmethod
    def askyesno(title, message, parent=None, **_kwargs):
        dialog = ConfirmDialog(parent, title, message, tone="warning")
        dialog.wait_window()
        if parent is not None and hasattr(parent, "grab_set"):
            parent.grab_set()
        return dialog.result


class UXSimpleDialog:
    @staticmethod
    def askstring(title, prompt, parent=None, initialvalue="", show=None, **_kwargs):
        dialog = InputDialog(parent, title, prompt, initialvalue=initialvalue, secret=bool(show))
        dialog.wait_window()
        return dialog.value

    @staticmethod
    def askinteger(title, prompt, parent=None, initialvalue=None, minvalue=None, maxvalue=None, **_kwargs):
        def parse(value):
            number = int(value)
            if minvalue is not None and number < minvalue:
                raise ValueError(f"Giá trị phải từ {minvalue} trở lên.")
            if maxvalue is not None and number > maxvalue:
                raise ValueError(f"Giá trị không được vượt quá {maxvalue}.")
            return number

        dialog = InputDialog(parent, title, prompt, initialvalue="" if initialvalue is None else str(initialvalue), validator=parse)
        dialog.wait_window()
        return dialog.value


class ToastManager:
    """Non-blocking notification stack anchored to the app window."""

    def __init__(self, parent):
        self.parent = parent.winfo_toplevel() if hasattr(parent, "winfo_toplevel") else parent
        self.items = []

    def push(self, title: str, message: str, tone: str = "info", duration: int = 4200):
        color = {"success": COLORS["green"], "warning": COLORS["amber"], "error": COLORS["red"], "info": COLORS["cyan"]}.get(tone, COLORS["cyan"])
        soft = {"success": COLORS["success_soft"], "warning": COLORS["warning_soft"], "error": COLORS["danger_soft"], "info": COLORS["info_soft"]}.get(tone, COLORS["info_soft"])
        toast = tk.Frame(self.parent, bg=soft, highlightbackground=COLORS["border"], highlightthickness=1)
        tk.Frame(toast, bg=color, width=5).pack(side="left", fill="y")
        body = tk.Frame(toast, bg=soft)
        body.pack(side="left", fill="both", expand=True, padx=13, pady=10)
        tk.Label(body, text=title, fg=COLORS["text"], bg=soft, font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x")
        tk.Label(body, text=message, fg=COLORS["muted"], bg=soft, font=("Segoe UI", 8), justify="left", wraplength=305, anchor="w").pack(fill="x", pady=(3, 0))
        close = tk.Label(toast, text="×", fg=COLORS["muted"], bg=soft, font=("Segoe UI", 14, "bold"), cursor="hand2")
        close.pack(side="right", padx=10, pady=8, anchor="n")
        close.bind("<Button-1>", lambda _event: self._remove(toast))
        self.items.append(toast)
        self._reflow()
        toast.after(duration, lambda: self._remove(toast))

    def _remove(self, toast):
        if toast in self.items:
            self.items.remove(toast)
            toast.destroy()
            self._reflow()

    def _reflow(self):
        for index, toast in enumerate(self.items):
            toast.place(relx=1.0, rely=1.0, anchor="se", x=-24, y=-24 - (index * 86), width=390)
