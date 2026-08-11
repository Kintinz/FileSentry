"""FileSentry security-console UI.

The UI deliberately separates low-risk read-only views from protected actions.
Every action that changes protection or scope goes through PasswordGate.
"""

from __future__ import annotations

import io
import os
import tkinter as tk
from datetime import datetime
from pathlib import Path
from threading import Event, Thread
from tkinter import filedialog, ttk

try:
    from PIL import Image, ImageTk
except ImportError:  # Image preview remains available through Windows defaults.
    Image = None
    ImageTk = None

from core.media_guard import MediaGuardError
from core.incident_report import IncidentReportBuilder
from core.branding import PRODUCT_NAME
from core.uninstall import UninstallError, UninstallManager
from .guides import GuidePopup
from .design_system import (
    COLORS,
    UXMessageBox,
    UXSimpleDialog,
    ToastManager,
    apply_theme_mode,
    configure_ttk_style,
    make_button,
    resolve_theme_mode,
    status_pill,
)


messagebox = UXMessageBox()
simpledialog = UXSimpleDialog()


# FileSentry is presented as one protection journey.  Individual screens are
# still available for detail, but the workflow bar and dashboard always show
# where the user is in the same lifecycle.
WORKFLOW_STEPS = (
    ("overview", "TỔNG QUAN", "Nhìn toàn bộ trạng thái", "dashboard"),
    ("scope", "PHẠM VI", "Chọn nơi cần bảo vệ", "scope"),
    ("policy", "CHÍNH SÁCH", "Chọn cách bảo vệ", "access"),
    ("monitor", "THEO DÕI", "Kiểm tra tín hiệu", "activity"),
    ("recover", "XỬ LÝ", "Cách ly và khôi phục", "quarantine"),
)
PAGE_WORKFLOW = {
    "dashboard": "overview",
    "scope": "scope",
    "media_library": "policy",
    "media": "policy",
    "access": "policy",
    "vault": "policy",
    "activity": "monitor",
    "network": "monitor",
    "persistence": "monitor",
    "quarantine": "recover",
    "settings": "overview",
}

CARD_ICONS = {
    "KHU VỰC": "▣",
    "SỰ KIỆN": "≡",
    "CẢNH BÁO": "!",
    "QUARANTINE": "◇",
    "ẢNH": "▧",
    "VIDEO": "▷",
    "ÂM THANH": "◖",
    "KHO RIÊNG": "◆",
    "SOCKET": "◌",
    "INTERNET": "◎",
    "BACKEND": "⌘",
    "LẦN QUÉT": "↻",
}


class WindowChrome(tk.Frame):
    """Custom Windows title bar used by the login and security console."""

    is_window_chrome = True

    def __init__(self, master, title: str):
        super().__init__(master, height=38, bd=0, highlightthickness=0)
        self.master = master
        self.title_text = title
        self._normal_geometry = None
        self._maximized = False
        try:
            master.overrideredirect(True)
        except tk.TclError:
            pass
        self.pack_propagate(False)
        self._build()
        self.refresh_theme()
        self._make_taskbar_window()

    def _build(self):
        self.brand_row = tk.Frame(self, bd=0, highlightthickness=0)
        self.brand_row.pack(side="left", fill="y", padx=(12, 0))
        self.mark = tk.Frame(self.brand_row, width=25, height=25, bd=0, highlightthickness=0)
        self.mark.pack(side="left", pady=6)
        self.mark.pack_propagate(False)
        self.mark_label = tk.Label(self.mark, text="FS", font=("Segoe UI", 9, "bold"), bd=0)
        self.mark_label.pack(expand=True)
        self.title_label = tk.Label(self.brand_row, text=self.title_text, font=("Segoe UI", 9, "bold"), anchor="w")
        self.title_label.pack(side="left", padx=(9, 7))
        self.subtitle_label = tk.Label(self.brand_row, text="LOCAL SECURITY CONSOLE", font=("Segoe UI", 7, "bold"), anchor="w")
        self.subtitle_label.pack(side="left", padx=(0, 16))

        self.controls = tk.Frame(self, bd=0, highlightthickness=0)
        self.controls.pack(side="right", fill="y")
        self.theme_button = self._control("◐", self._open_theme_menu, "Đổi giao diện")
        self.theme_button.configure(state="disabled")
        self.minimize_button = self._control("—", self.minimize, "Thu nhỏ")
        self.maximize_button = self._control("□", self.toggle_maximize, "Phóng to / khôi phục")
        self.close_button = self._control("×", self.close, "Đóng")

        for widget in (self, self.brand_row, self.mark, self.mark_label, self.title_label, self.subtitle_label):
            widget.bind("<ButtonPress-1>", self._start_drag, add="+")
            widget.bind("<B1-Motion>", self._drag, add="+")
            widget.bind("<Double-Button-1>", lambda _event: self.toggle_maximize(), add="+")

    def _control(self, text, command, tooltip):
        button = tk.Button(
            self.controls,
            text=text,
            command=command,
            width=4,
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=("Segoe UI", 10),
            cursor="hand2",
        )
        button.pack(side="left", fill="y")
        button.bind("<Enter>", lambda _event, b=button: b.configure(bg=COLORS["panel_elevated"], fg=COLORS["text"]) if str(b.cget("state")) != "disabled" else None)
        button.bind("<Leave>", lambda _event, b=button: b.configure(bg=COLORS["sidebar"], fg=COLORS["muted"]) if str(b.cget("state")) != "disabled" else None)
        button.configure(takefocus=True)
        button.tooltip_text = tooltip
        return button

    def set_theme_callback(self, callback, icon: str):
        self.theme_button.configure(command=callback, text=icon, state="normal")

    def _open_theme_menu(self):
        callback = getattr(self, "_theme_callback", None)
        if callback is not None:
            callback()

    def refresh_theme(self):
        bar_bg = COLORS["sidebar"]
        self.configure(bg=bar_bg)
        self.brand_row.configure(bg=bar_bg)
        self.controls.configure(bg=bar_bg)
        self.mark.configure(bg=COLORS["cyan"])
        self.mark_label.configure(bg=COLORS["cyan"], fg=COLORS["bg"])
        self.title_label.configure(bg=bar_bg, fg=COLORS["text"])
        self.subtitle_label.configure(bg=bar_bg, fg=COLORS["cyan"])
        for button in (self.theme_button, self.minimize_button, self.maximize_button, self.close_button):
            button.configure(bg=bar_bg, fg=COLORS["muted"], activebackground=COLORS["panel_elevated"], activeforeground=COLORS["text"])
        self.close_button.configure(activebackground=COLORS["red"])

    def _make_taskbar_window(self):
        """Keep the borderless window discoverable from the Windows taskbar."""
        if os.name != "nt":
            return
        try:
            import ctypes

            hwnd = self.master.winfo_id()
            get_long = ctypes.windll.user32.GetWindowLongW
            set_long = ctypes.windll.user32.SetWindowLongW
            style = get_long(hwnd, -20)
            set_long(hwnd, -20, (style | 0x00040000) & ~0x00000080)  # APPWINDOW, not TOOLWINDOW
            ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0027)
        except (AttributeError, OSError, tk.TclError):
            pass

    def _start_drag(self, event):
        if self._maximized:
            return
        self._drag_offset_x = event.x_root - self.master.winfo_x()
        self._drag_offset_y = event.y_root - self.master.winfo_y()

    def _drag(self, event):
        if self._maximized or not hasattr(self, "_drag_offset_x"):
            return
        x = event.x_root - self._drag_offset_x
        y = event.y_root - self._drag_offset_y
        self.master.geometry(f"+{x}+{y}")

    def toggle_maximize(self):
        if self._maximized:
            if self._normal_geometry:
                self.master.geometry(self._normal_geometry)
            self._maximized = False
            self.maximize_button.configure(text="□")
            return
        self._normal_geometry = self.master.geometry()
        try:
            self.master.state("zoomed")
        except tk.TclError:
            self.master.geometry(f"{self.master.winfo_screenwidth()}x{self.master.winfo_screenheight()}+0+0")
        self._maximized = True
        self.maximize_button.configure(text="❐")

    def minimize(self):
        try:
            if os.name == "nt":
                import ctypes

                ctypes.windll.user32.ShowWindow(self.master.winfo_id(), 6)
            else:
                self.master.iconify()
        except (AttributeError, OSError, tk.TclError):
            self.master.iconify()

    def close(self):
        self.master.destroy()


def install_window_chrome(window, title: str = PRODUCT_NAME):
    chrome = getattr(window, "_filesentry_chrome", None)
    if chrome is not None and chrome.winfo_exists():
        return chrome
    chrome = WindowChrome(window, title)
    chrome.pack(side="top", fill="x")
    window._filesentry_chrome = chrome
    return chrome


class PasswordGate(tk.Toplevel):
    """Modal password check for every protected operation."""

    def __init__(self, parent, controller, username, title, description, on_success):
        super().__init__(parent)
        self.parent = parent
        self.controller = controller
        self.username = username
        self.on_success = on_success
        self.title("Xác thực bảo mật")
        self.configure(bg=COLORS["panel"])
        self.geometry("540x365")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        top = tk.Frame(self, bg=COLORS["panel_alt"])
        top.pack(fill="x")
        tk.Frame(top, bg=COLORS["amber"], width=6).pack(side="left", fill="y")
        tk.Label(top, text="FS", fg=COLORS["bg"], bg=COLORS["cyan"], font=("Segoe UI", 16, "bold"), width=3).pack(side="left", padx=(20, 12), pady=18)
        text = tk.Frame(top, bg=COLORS["panel_alt"])
        text.pack(side="left", fill="x", expand=True)
        tk.Label(text, text=title, fg=COLORS["text"], bg=COLORS["panel_alt"], anchor="w", font=("Segoe UI", 14, "bold")).pack(fill="x", pady=(15, 1))
        tk.Label(text, text="Cổng xác thực duy nhất cho thao tác nhạy cảm", fg=COLORS["muted"], bg=COLORS["panel_alt"], anchor="w", font=("Segoe UI", 8)).pack(fill="x", pady=(0, 15))
        notice = tk.Frame(self, bg=COLORS["info_soft"], highlightbackground=COLORS["amber"], highlightthickness=1)
        notice.pack(fill="x", padx=26, pady=(18, 14))
        tk.Label(notice, text="AUTHORIZATION REQUIRED", fg=COLORS["cyan"], bg=COLORS["info_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=14, pady=(11, 3))
        tk.Label(notice, text=description, justify="left", wraplength=450, fg=COLORS["muted"], bg=COLORS["info_soft"], anchor="w", font=("Segoe UI", 9)).pack(fill="x", padx=14, pady=(0, 11))
        form = tk.Frame(self, bg=COLORS["panel"])
        form.pack(fill="x", padx=26)
        tk.Label(form, text=f"TÀI KHOẢN QUẢN TRỊ  /  {username}", fg=COLORS["subtle"], bg=COLORS["panel"], anchor="w", font=("Segoe UI", 8, "bold")).pack(fill="x")
        password_row = tk.Frame(form, bg=COLORS["panel"])
        password_row.pack(fill="x", pady=(5, 0))
        self.password = tk.Entry(password_row, show="•", bg=COLORS["panel_alt"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", font=("Segoe UI", 11))
        self.password.pack(side="left", fill="x", expand=True, ipady=8)
        self.reveal = make_button(password_row, "HIỆN", self._toggle_password, bg=COLORS["panel_elevated"], fg=COLORS["muted"], small=True, outline=True)
        self.reveal.pack(side="left", padx=(8, 0))
        self.password.bind("<Return>", lambda _event: self.verify())
        self.error = tk.Label(self, text="", fg=COLORS["red"], bg=COLORS["panel"], font=("Segoe UI", 8), anchor="w")
        self.error.pack(fill="x", padx=26, pady=(6, 0))
        footer = tk.Frame(self, bg=COLORS["panel"])
        footer.pack(fill="x", padx=26, pady=(7, 20))
        make_button(footer, "HỦY", self.destroy, bg=COLORS["bg"], fg=COLORS["subtle"], outline=True).pack(side="right", padx=(8, 0))
        primary = make_button(footer, "XÁC THỰC VÀ TIẾP TỤC", self.verify, bg=COLORS["cyan"], fg=COLORS["bg"])
        primary.configure(highlightthickness=1, highlightbackground=COLORS["cyan"])
        primary.pack(side="right")
        self.password.focus_set()

    def _toggle_password(self):
        visible = self.password.cget("show") == ""
        self.password.configure(show="•" if visible else "")
        self.reveal.configure(text="HIỆN" if visible else "ẨN")

    def verify(self):
        valid, _ = self.controller.auth.authenticate(self.username, self.password.get())
        if not valid:
            self.error.configure(text="Mật khẩu không đúng. Thao tác đã bị từ chối.")
            self.password.delete(0, "end")
            return
        self.controller.auth_session.open(self.username)
        self.controller.db.record_audit("protected_action_authenticated", {"username": self.username})
        self.destroy()
        self.on_success()


class LoginView(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master, bg=COLORS["bg"])
        self.master = master
        self.controller = controller
        self._build()

    def _build(self):
        self.master.configure(bg=COLORS["bg"])
        self.master.geometry("620x720")
        self.master.minsize(540, 640)
        card = tk.Frame(self, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center", width=480, height=535)
        tk.Frame(card, bg=COLORS["cyan"], height=5).pack(fill="x")
        brand = tk.Frame(card, bg=COLORS["panel_alt"])
        brand.pack(fill="x", pady=(0, 22))
        tk.Label(brand, text="FS", fg=COLORS["bg"], bg=COLORS["cyan"], font=("Segoe UI", 20, "bold"), width=3).pack(side="left", padx=(28, 14), pady=24)
        brand_text = tk.Frame(brand, bg=COLORS["panel_alt"])
        brand_text.pack(side="left", anchor="w")
        tk.Label(brand_text, text=PRODUCT_NAME, fg=COLORS["text"], bg=COLORS["panel_alt"], font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(brand_text, text="SECURITY CONSOLE  /  LOCAL WINDOWS", fg=COLORS["cyan"], bg=COLORS["panel_alt"], font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(3, 0))
        tk.Label(card, text="Đăng nhập để quản lý trạng thái bảo vệ trên thiết bị này", fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 9)).pack(anchor="w", padx=45, pady=(0, 20))
        form = tk.Frame(card, bg=COLORS["panel"])
        form.pack(fill="x", padx=45)
        self.username = self._field(form, "TÀI KHOẢN QUẢN TRỊ", "admin")
        self.password = self._field(form, "MẬT KHẨU", "")
        self.password.configure(show="•")
        self.password.bind("<Return>", lambda _event: self.login())
        self.error = tk.Label(card, text="", fg=COLORS["red"], bg=COLORS["panel"], font=("Segoe UI", 8), anchor="w")
        self.error.pack(fill="x", padx=45, pady=(1, 5))
        make_button(card, "ĐĂNG NHẬP VÀO CONSOLE", self.login, bg=COLORS["cyan"], fg=COLORS["bg"]).pack(fill="x", padx=45, pady=(2, 0), ipady=2)
        security = tk.Frame(card, bg=COLORS["info_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        security.pack(fill="x", padx=45, pady=(24, 0))
        tk.Label(security, text="LOCAL SECURITY SESSION", fg=COLORS["cyan"], bg=COLORS["info_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=13, pady=(11, 3))
        tk.Label(security, text="Không gửi mật khẩu, file hoặc telemetry ra ngoài.\nPhiên xác thực thông thường tự hết hạn sau 15 phút.", fg=COLORS["muted"], bg=COLORS["info_soft"], font=("Segoe UI", 8), justify="left").pack(anchor="w", padx=13, pady=(0, 11))
        tk.Label(card, text="Tài khoản khởi tạo: admin  •  mật khẩu phải đổi ở lần đăng nhập đầu tiên", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 8), justify="center").pack(pady=(18, 0))

    def _field(self, parent, label, value):
        tk.Label(parent, text=label, fg=COLORS["muted"], bg=COLORS["panel"], anchor="w", font=("Segoe UI", 8, "bold")).pack(fill="x")
        entry = tk.Entry(parent, bg=COLORS["panel_alt"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", font=("Segoe UI", 11))
        entry.insert(0, value)
        entry.pack(fill="x", ipady=7, pady=(4, 13))
        return entry

    def login(self):
        username, password = self.username.get().strip(), self.password.get()
        valid, must_change = self.controller.auth.authenticate(username, password)
        if not valid:
            self.error.configure(text="Tài khoản hoặc mật khẩu không đúng.")
            self.password.delete(0, "end")
            return
        if must_change and not self.change_password(username, password):
            return
        self.controller.auth_session.open(username)
        for child in self.master.winfo_children():
            if getattr(child, "is_window_chrome", False):
                continue
            child.destroy()
        FileSentryApp(self.master, self.controller, username).pack(fill="both", expand=True)

    def change_password(self, username, current):
        dialog = tk.Toplevel(self.master)
        dialog.title("Đổi mật khẩu bắt buộc")
        dialog.configure(bg=COLORS["panel"])
        dialog.geometry("500x405")
        dialog.resizable(False, False)
        dialog.transient(self.master)
        dialog.grab_set()
        tk.Frame(dialog, bg=COLORS["cyan"], height=4).pack(fill="x")
        header = tk.Frame(dialog, bg=COLORS["panel_alt"])
        header.pack(fill="x")
        tk.Label(header, text="FS", fg=COLORS["bg"], bg=COLORS["cyan"], font=("Segoe UI", 14, "bold"), width=3).pack(side="left", padx=(24, 12), pady=16)
        text = tk.Frame(header, bg=COLORS["panel_alt"])
        text.pack(side="left", anchor="w")
        tk.Label(text, text="Thiết lập mật khẩu mới", fg=COLORS["text"], bg=COLORS["panel_alt"], font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(text, text="Bắt buộc sau lần đăng nhập đầu tiên", fg=COLORS["muted"], bg=COLORS["panel_alt"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        tk.Label(dialog, text="Mật khẩu khởi tạo chỉ dùng một lần. Hãy đặt mật khẩu riêng cho máy này.", fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 9), wraplength=420, justify="left").pack(anchor="w", padx=40, pady=(18, 12))
        frame = tk.Frame(dialog, bg=COLORS["panel"])
        frame.pack(fill="x", padx=40)
        first = self._dialog_field(frame, "Mật khẩu mới")
        second = self._dialog_field(frame, "Nhập lại mật khẩu")
        result = {"ok": False}

        def save():
            if first.get() != second.get():
                messagebox.showerror("Không khớp", "Hai mật khẩu chưa giống nhau.", parent=dialog)
                return
            try:
                self.controller.auth.change_password(username, current, first.get())
            except ValueError as exc:
                messagebox.showerror("Mật khẩu chưa hợp lệ", str(exc), parent=dialog)
                return
            result["ok"] = True
            dialog.destroy()

        note = tk.Label(dialog, text="Khuyến nghị: tối thiểu 12 ký tự, gồm chữ hoa, chữ thường, số và ký tự đặc biệt.", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 8), wraplength=420, justify="left")
        note.pack(anchor="w", padx=40, pady=(2, 10))
        make_button(dialog, "LƯU MẬT KHẨU", save, bg=COLORS["cyan"], fg=COLORS["bg"]).pack(fill="x", padx=40, pady=(0, 20))
        self.master.wait_window(dialog)
        return result["ok"]

    def _dialog_field(self, parent, label):
        tk.Label(parent, text=label, fg=COLORS["muted"], bg=COLORS["panel"], anchor="w").pack(fill="x")
        entry = tk.Entry(parent, show="•", bg=COLORS["panel_alt"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat")
        entry.pack(fill="x", ipady=6, pady=(3, 9))
        return entry


class FileSentryApp(tk.Frame):
    def __init__(self, master, controller, username):
        super().__init__(master, bg=COLORS["bg"])
        chrome = install_window_chrome(master, PRODUCT_NAME)
        master.title(PRODUCT_NAME)
        master.geometry("1320x820")
        master.minsize(1080, 700)
        self.controller = controller
        self.username = username
        self.theme_mode = self.controller.settings.data.get("theme_mode", "system")
        self._resolved_theme = apply_theme_mode(self.theme_mode)
        chrome.refresh_theme()
        chrome.set_theme_callback(self.open_theme_menu, self._theme_icon())
        self._theme_button = chrome.theme_button
        self.current_page = "dashboard"
        self._last_status_marker = None
        self.media_site_trees = {}
        self._media_scan_running = False
        self._media_scan_cancel = None
        self._media_scan_dialog = None
        self._body_root = None
        self._visible_page_body = None
        self._update_refresh_scheduled = False
        self._page_status_pill = None
        self._guide_popup = None
        self._context_menu = None
        self._theme_menu = None
        self._workflow_detail_labels = {}
        # Live widget registry used by the interactive in-app guides.  Page
        # widgets are rebuilt when navigating, so the registry is refreshed
        # by show_page() and never stores a stale target permanently.
        self.guide_targets = {}
        self.toast_manager = ToastManager(self)
        self.controller.subscribe(self._on_update)
        self._style()
        self._build_shell()
        self.show_page("dashboard")
        self.after(650, self._maybe_show_onboarding)
        self.after(1000, self._tick)

    def _style(self):
        configure_ttk_style(self)

    @staticmethod
    def _theme_label(mode: str) -> str:
        return {
            "system": "Theo Windows",
            "light": "Ban ngày",
            "dark": "Ban đêm",
        }.get(str(mode).lower(), "Theo Windows")

    def _theme_icon(self) -> str:
        return {"system": "◐", "light": "☼", "dark": "☾"}.get(self.theme_mode, "◐")

    def open_theme_menu(self):
        if self._theme_menu is not None:
            try:
                self._theme_menu.destroy()
            except tk.TclError:
                pass
        menu = tk.Menu(
            self,
            tearoff=False,
            bg=COLORS["panel_alt"],
            fg=COLORS["text"],
            activebackground=COLORS["cyan"],
            activeforeground=COLORS["bg"],
            bd=0,
            relief="flat",
            font=("Segoe UI", 9),
        )
        menu.add_command(label="CHẾ ĐỘ GIAO DIỆN", state="disabled")
        menu.add_separator()
        for mode in ("system", "light", "dark"):
            marker = "✓  " if mode == self.theme_mode else "    "
            menu.add_command(
                label=f"{marker}{self._theme_label(mode)}",
                command=lambda value=mode: self.set_theme_mode(value),
            )
        self._theme_menu = menu
        button = getattr(self, "_theme_button", None)
        if button is not None and button.winfo_exists():
            x = button.winfo_rootx()
            y = button.winfo_rooty() + button.winfo_height() + 5
        else:
            x = self.winfo_toplevel().winfo_rootx() + self.winfo_toplevel().winfo_width() - 220
            y = self.winfo_toplevel().winfo_rooty() + 90
        try:
            menu.tk_popup(x, y)
        finally:
            try:
                menu.grab_release()
            except tk.TclError:
                pass

    def set_theme_mode(self, mode: str):
        """Persist the visual preference and redraw the shell atomically."""
        normalized = str(mode or "system").lower()
        if normalized not in {"system", "light", "dark"}:
            return
        self.theme_mode = normalized
        self.controller.settings.save({"theme_mode": normalized})
        self._resolved_theme = apply_theme_mode(normalized)
        self._rebuild_for_theme()
        self.toast(
            "Đã đổi giao diện",
            f"Đang dùng: {self._theme_label(normalized)} · {self._theme_label(self._resolved_theme)}.",
            "success",
        )

    def _rebuild_for_theme(self):
        """Recreate themed widgets without touching controller state or data."""
        if self._guide_popup is not None:
            try:
                if self._guide_popup.winfo_exists():
                    self._guide_popup.close()
            except tk.TclError:
                pass
            self._guide_popup = None
        if self._context_menu is not None:
            try:
                self._context_menu.destroy()
            except tk.TclError:
                pass
            self._context_menu = None
        theme_menu = getattr(self, "_theme_menu", None)
        if theme_menu is not None:
            try:
                theme_menu.destroy()
            except tk.TclError:
                pass
            self._theme_menu = None
        for toast in list(self.toast_manager.items):
            try:
                toast.destroy()
            except tk.TclError:
                pass
        self.toast_manager.items.clear()
        old_sidebar = getattr(self, "sidebar", None)
        old_body_root = getattr(self, "_body_root", None)
        for widget in (old_sidebar, old_body_root):
            try:
                if widget is not None and widget.winfo_exists():
                    widget.destroy()
            except tk.TclError:
                pass
        self._body_root = None
        self._visible_page_body = None
        self._page_status_pill = None
        self._workflow_detail_labels = {}
        self.guide_targets = {}
        self._style()
        chrome = getattr(self.winfo_toplevel(), "_filesentry_chrome", None)
        if chrome is not None:
            chrome.refresh_theme()
            chrome.set_theme_callback(self.open_theme_menu, self._theme_icon())
            self._theme_button = chrome.theme_button
        self._build_shell()
        self.show_page(self.current_page)

    def _sync_system_theme(self):
        if self.theme_mode != "system":
            return False
        resolved = resolve_theme_mode("system")
        if resolved == self._resolved_theme:
            return False
        self._resolved_theme = apply_theme_mode("system")
        self._rebuild_for_theme()
        return True

    def _scrollable_tree(self, parent, columns, **options):
        """Create a Treeview with both vertical and horizontal scrolling."""
        host = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        tree = ttk.Treeview(host, columns=columns, show="headings", **options)
        vertical = ttk.Scrollbar(host, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(host, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew", padx=(1, 0), pady=(1, 0))
        vertical.grid(row=0, column=1, sticky="ns", pady=(1, 0))
        horizontal.grid(row=1, column=0, sticky="ew", padx=(1, 0))
        host.grid_rowconfigure(0, weight=1)
        host.grid_columnconfigure(0, weight=1)
        return tree, host

    def _bind_context_targets(self, widget):
        """Give each screen and its data tables a consistent right-click menu."""
        if isinstance(widget, ttk.Treeview):
            widget.bind("<Button-3>", self._on_context_menu, add="+")
            return
        widget.bind("<Button-3>", self._on_context_menu, add="+")
        for child in widget.winfo_children():
            self._bind_context_targets(child)

    def _menu_items(self, items):
        """Create a themed context menu from (label, command, state) tuples."""
        menu = tk.Menu(
            self,
            tearoff=False,
            bg=COLORS["panel_alt"],
            fg=COLORS["text"],
            activebackground=COLORS["cyan"],
            activeforeground=COLORS["bg"],
            bd=0,
            relief="flat",
            font=("Segoe UI", 9),
        )
        for item in items:
            if item is None:
                menu.add_separator()
                continue
            label, command, state = item if len(item) == 3 else (*item, "normal")
            menu.add_command(label=label, command=command, state=state)
        return menu

    def _post_context_menu(self, event, items):
        if self._context_menu is not None:
            try:
                self._context_menu.unpost()
                self._context_menu.destroy()
            except tk.TclError:
                pass
        self._context_menu = self._menu_items(items)
        try:
            self._context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            try:
                self._context_menu.grab_release()
            except tk.TclError:
                pass
            self._context_menu = None

    def _common_context_items(self):
        return [
            ("Làm mới màn hình", lambda: self.show_page(self.current_page)),
            ("Mở hướng dẫn thao tác", lambda: self.open_guide(self.current_page)),
        ]

    def _page_context_items(self):
        page = self.current_page
        items = self._common_context_items() + [None]
        page_actions = {
            "dashboard": [
                ("Bật / tắt bảo vệ", self.toggle_protection),
                ("Tạm dừng 15 phút", lambda: self.pause(15)),
                ("Mở khu vực bảo vệ", self.open_protected_scope),
            ],
            "scope": [
                ("Thêm khu vực include", lambda: self.add_path("include")),
                ("Thêm khu vực exclude", lambda: self.add_path("exclude")),
                ("Tạo kho lưu trữ riêng", self.create_protected_storage),
            ],
            "access": [
                ("Mở Camera & Microphone", lambda: self.show_page("media")),
                ("Mở Media Library", lambda: self.show_page("media_library")),
                ("Mở Kho mã hóa", self.open_vault_page),
                ("Mở Khu vực bảo vệ", self.open_protected_scope),
            ],
            "media_library": [
                ("Đồng bộ toàn bộ máy", self.scan_media_library),
                ("Thêm file media", self.add_media_file),
                ("Xóa inventory, giữ file thật", self.clear_media_library_inventory),
            ],
            "media": [
                ("Mở Camera & Microphone", lambda: self.show_page("media")),
                ("Mở Windows Privacy Settings — Camera", lambda: self.open_media_settings("camera")),
                ("Mở Windows Privacy Settings — Microphone", lambda: self.open_media_settings("microphone")),
            ],
            "vault": [("Đưa file vào Vault", self.vault_import)],
            "activity": [
                ("Xuất báo cáo sự cố", self.export_incident_report),
                ("Mở báo cáo sự cố", self.open_incident_report),
            ],
            "network": [("Quét lại kết nối", lambda: (self.controller.network.scan_once(), self.show_page("network")))],
            "persistence": [("Quét lại persistence", lambda: (self.controller.persistence.scan_once(), self.show_page("persistence")))],
            "quarantine": [],
            "settings": [
                ("Đổi mật khẩu quản trị", self.change_password),
                ("Mở khóa khẩn cấp Folder Lock", self.emergency_unlock_all_folders),
                ("Gỡ FileSentry", self.uninstall_app),
            ],
        }
        return items + page_actions.get(page, [])

    def _tree_context_items(self, tree):
        columns = set(str(column) for column in tree["columns"])
        selected = bool(tree.selection())
        items = self._common_context_items() + [None]
        page = self.current_page
        if page == "media_library" and {"name", "location", "delete", "export"}.issubset(columns):
            items.extend([
                ("Xem / mở media đang chọn", self.view_selected_media, "normal" if selected else "disabled"),
                ("Khóa xóa file đang chọn", self.protect_selected_media, "normal" if selected else "disabled"),
                ("Chống gửi ra ngoài", self.secure_selected_media, "normal" if selected else "disabled"),
                ("Gỡ bảo vệ file", self.remove_selected_media_policy, "normal" if selected else "disabled"),
            ])
        elif page == "vault" and "source" in columns:
            items.append(("Khôi phục mục đang chọn", lambda: self.vault_restore(tree), "normal" if selected else "disabled"))
        elif page == "quarantine" and "reason" in columns:
            items.append(("Khôi phục mục đang chọn", lambda: self.restore_quarantine(tree), "normal" if selected else "disabled"))
        elif page == "scope":
            if "kind" in columns:
                items.append(("Xóa bảo vệ mục đang chọn", self.remove_selected_scope, "normal" if selected else "disabled"))
            elif "sid" in columns:
                items.extend([
                    ("Mở khóa Folder Lock đang chọn", self.unlock_selected_folder, "normal" if selected else "disabled"),
                    ("Kiểm tra toàn vẹn ACL", self.verify_folder_locks, "normal"),
                ])
            elif "created" in columns and "name" in columns:
                items.extend([
                    ("Mở thư mục đang chọn", self.open_selected_storage, "normal" if selected else "disabled"),
                    ("Gỡ quản lý, giữ thư mục", self.remove_selected_storage, "normal" if selected else "disabled"),
                ])
        elif page == "media" and "origin" in columns:
            kind = next((value for value, candidate in self.media_site_trees.items() if candidate is tree), "camera")
            items.append(("Xóa website origin đang chọn", lambda k=kind: self.remove_media_site(k), "normal" if selected else "disabled"))
        elif page == "network":
            items.append(("Quét lại kết nối", lambda: (self.controller.network.scan_once(), self.show_page("network")), "normal"))
        elif page == "persistence":
            items.append(("Quét lại persistence", lambda: (self.controller.persistence.scan_once(), self.show_page("persistence")), "normal"))
        elif page == "activity":
            items.append(("Xuất báo cáo sự cố", self.export_incident_report, "normal"))
        return items

    def _on_context_menu(self, event):
        widget = event.widget
        if isinstance(widget, ttk.Treeview):
            row = widget.identify_row(event.y)
            if row:
                widget.selection_set(row)
                widget.focus(row)
            self._post_context_menu(event, self._tree_context_items(widget))
        else:
            self._post_context_menu(event, self._page_context_items())
        return "break"

    def toast(self, title: str, message: str, tone: str = "info"):
        """Show a non-blocking notification without interrupting the workflow."""
        self.toast_manager.push(title, message, tone)

    def _build_shell(self):
        self.sidebar = tk.Frame(self, bg=COLORS["sidebar"], width=270)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        brand = tk.Frame(self.sidebar, bg=COLORS["sidebar"])
        brand.pack(fill="x", padx=18, pady=(24, 18))
        mark = tk.Frame(brand, bg=COLORS["cyan"], width=42, height=42)
        mark.pack(side="left")
        mark.pack_propagate(False)
        tk.Label(mark, text="FS", fg=COLORS["bg"], bg=COLORS["cyan"], font=("Segoe UI", 15, "bold")).pack(expand=True)
        brand_text = tk.Frame(brand, bg=COLORS["sidebar"], width=174, height=44)
        brand_text.pack(side="left", padx=(11, 0))
        brand_text.pack_propagate(False)
        tk.Label(brand_text, text=PRODUCT_NAME, fg=COLORS["text"], bg=COLORS["sidebar"], font=("Segoe UI", 14, "bold"), anchor="w").pack(fill="x", pady=(1, 0))
        tk.Label(brand_text, text="ENDPOINT SECURITY CONSOLE", fg=COLORS["cyan"], bg=COLORS["sidebar"], font=("Segoe UI", 7, "bold")).pack(anchor="w", pady=(3, 0))
        tk.Frame(self.sidebar, bg=COLORS["border_soft"], height=1).pack(fill="x", padx=22, pady=(0, 16))

        self.sidebar_device = tk.Frame(self.sidebar, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        self.sidebar_device.pack(fill="x", padx=18, pady=(0, 17))
        device_top = tk.Frame(self.sidebar_device, bg=COLORS["panel"])
        device_top.pack(fill="x", padx=13, pady=(12, 5))
        tk.Label(device_top, text="DEVICE POSTURE", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 7, "bold")).pack(side="left")
        tk.Label(device_top, text="LOCAL", fg=COLORS["cyan"], bg=COLORS["panel"], font=("Segoe UI", 7, "bold")).pack(side="right")
        self.sidebar_device_status = tk.Label(self.sidebar_device, text="●  Đang kiểm tra trạng thái", fg=COLORS["green"], bg=COLORS["panel"], font=("Segoe UI", 9, "bold"), anchor="w")
        self.sidebar_device_status.pack(fill="x", padx=13)
        tk.Label(self.sidebar_device, text="Mọi dữ liệu và khóa mã hóa chỉ lưu trên thiết bị này.", fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 8), justify="left", wraplength=210, anchor="w").pack(fill="x", padx=13, pady=(4, 12))
        self.nav_buttons = {}
        self.nav_indicators = {}
        self.nav_icons = {}
        nav_groups = (
            ("WORKFLOW", (("dashboard", "Tổng quan", "⌂"), ("scope", "Khu vực bảo vệ", "▣"), ("access", "Access Center", "✦"))),
            ("PROTECTION", (("media_library", "Ảnh / Video / Âm thanh", "◈"), ("media", "Camera & Microphone", "◉"), ("vault", "Kho mã hóa", "◆"))),
            ("VISIBILITY", (("activity", "Nhật ký hoạt động", "≡"), ("network", "Kết nối mạng", "◌"), ("persistence", "Startup & Persistence", "◇"))),
            ("RECOVERY & SYSTEM", (("quarantine", "Cách ly", "◇"), ("settings", "Cài đặt hệ thống", "⚙"))),
        )
        for group_index, (group_name, nav_items) in enumerate(nav_groups):
            if group_index:
                tk.Frame(self.sidebar, bg=COLORS["border_soft"], height=1).pack(fill="x", padx=24, pady=(8, 8))
            tk.Label(self.sidebar, text=group_name, fg=COLORS["subtle"], bg=COLORS["sidebar"], font=("Segoe UI", 7, "bold")).pack(anchor="w", padx=24, pady=(6 if group_index else 0, 4))
            for key, label, icon in nav_items:
                if key == "scope":
                    command = self.open_protected_scope
                elif key == "vault":
                    command = self.open_vault_page
                else:
                    command = lambda value=key: self.show_page(value)
                row = tk.Frame(self.sidebar, bg=COLORS["sidebar"])
                row.pack(fill="x", padx=13, pady=2)
                indicator = tk.Frame(row, bg=COLORS["sidebar"], width=3)
                indicator.pack(side="left", fill="y")
                icon_label = tk.Label(row, text=icon, fg=COLORS["muted"], bg=COLORS["sidebar"], width=3, font=("Segoe UI", 10), cursor="hand2")
                icon_label.pack(side="left", padx=(7, 0))
                icon_label.bind("<Button-1>", lambda _event, fn=command: fn())
                button = tk.Button(row, text=label, command=command, anchor="w", bg=COLORS["sidebar"], fg=COLORS["muted"], activebackground=COLORS["panel_alt"], activeforeground=COLORS["text"], relief="flat", bd=0, highlightthickness=0, font=("Segoe UI", 10), cursor="hand2")
                button.pack(side="left", fill="x", expand=True, ipady=9)
                button.bind("<Enter>", lambda _event, b=button, i=indicator, l=icon_label, k=key: (b.configure(bg=COLORS["surface_hover"] if k != self.current_page else COLORS["sidebar_active"]), l.configure(bg=COLORS["surface_hover"] if k != self.current_page else COLORS["sidebar_active"], fg=COLORS["cyan"]), i.configure(bg=COLORS["cyan"] if k == self.current_page else COLORS["border"])))
                button.bind("<Leave>", lambda _event, b=button, i=indicator, l=icon_label, k=key: (b.configure(bg=COLORS["sidebar_active"] if k == self.current_page else COLORS["sidebar"]), l.configure(bg=COLORS["sidebar_active"] if k == self.current_page else COLORS["sidebar"], fg=COLORS["cyan"] if k == self.current_page else COLORS["muted"]), i.configure(bg=COLORS["cyan"] if k == self.current_page else COLORS["sidebar"])))
                self.nav_buttons[key] = button
                self.nav_indicators[key] = indicator
                self.nav_icons[key] = icon_label
                self._register_guide_target(f"nav_{key}", button)
        self.sidebar_help_button = make_button(self.sidebar, "?   HƯỚNG DẪN SỬ DỤNG", lambda: self.open_guide("quick_start"), bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True)
        self.sidebar_help_button.pack(fill="x", padx=22, pady=(14, 10))
        self._register_guide_target("sidebar_help", self.sidebar_help_button)
        tk.Label(self.sidebar, text="", bg=COLORS["sidebar"]).pack(expand=True, fill="both")
        self.sidebar_status = tk.Frame(self.sidebar, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        self.sidebar_status.pack(fill="x", padx=18, pady=(0, 12))
        tk.Label(self.sidebar_status, text="AUTHENTICATED SESSION", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 7, "bold")).pack(anchor="w", padx=12, pady=(10, 2))
        tk.Label(self.sidebar_status, text=f"●  {self.username}", fg=COLORS["green"], bg=COLORS["panel"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12)
        self.session_label = tk.Label(self.sidebar_status, text="Auth session: checking", fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 8))
        self.session_label.pack(anchor="w", padx=12, pady=(2, 10))
        meter_track = tk.Frame(self.sidebar_status, bg=COLORS["border_soft"], height=4)
        meter_track.pack(fill="x", padx=12, pady=(0, 12))
        meter_track.pack_propagate(False)
        self.session_meter = tk.Frame(meter_track, bg=COLORS["green"])
        self.session_meter.place(relx=0, rely=0, relwidth=0, relheight=1)
        self._register_guide_target("sidebar_session", self.session_label)
        tk.Label(self.sidebar, text="LOCAL-ONLY  •  ENCRYPTED BY DEFAULT", fg=COLORS["subtle"], bg=COLORS["sidebar"], font=("Segoe UI", 7, "bold")).pack(pady=(0, 17))
        self.body = tk.Frame(self, bg=COLORS["bg"])
        self.body.pack(side="left", fill="both", expand=True)
        self._body_root = self.body

    def _on_update(self):
        """Update lightweight status chrome without rebuilding the visible page.

        Controller notifications can come from watchdog/monitor threads. The
        previous implementation rebuilt every widget for every event, which
        briefly exposed an empty body and caused visible flicker. Page data is
        refreshed by explicit user actions/navigation; background updates only
        refresh the status pill.
        """
        if self._update_refresh_scheduled:
            return
        self._update_refresh_scheduled = True
        try:
            self.after(80, self._apply_lightweight_update)
        except tk.TclError:
            self._update_refresh_scheduled = False

    def _apply_lightweight_update(self):
        self._update_refresh_scheduled = False
        try:
            status = self.controller.status()
        except (OSError, RuntimeError, tk.TclError):
            return
        settings = status["settings"]
        marker = (status["label"], settings.get("enabled"), settings.get("pause_until"), status.get("access_locked"))
        if marker == self._last_status_marker:
            self._refresh_workflow_details()
            return
        self._last_status_marker = marker
        pill = self._page_status_pill
        if pill is None or not pill.winfo_exists():
            return
        pill.configure(bg=status["color"])
        for child in pill.winfo_children():
            child.configure(bg=status["color"], text=f"●  {status['label']}")
        self._refresh_workflow_details()

    def _refresh_workflow_details(self):
        details = self._workflow_details()
        for index, label in self._workflow_detail_labels.items():
            try:
                label.configure(text=details[max(0, index - 1)] if index else "Trung tâm điều khiển")
            except tk.TclError:
                pass

    def _maybe_show_onboarding(self):
        if not self.controller.settings.data.get("onboarding_seen", False):
            self.controller.settings.save({"onboarding_seen": True})
            self.open_guide("quick_start")

    def open_guide(self, guide_key: str | None = None):
        if self._guide_popup is not None:
            try:
                if self._guide_popup.winfo_exists():
                    self._guide_popup.close()
            except tk.TclError:
                pass
        self._guide_popup = GuidePopup(
            self,
            guide_key or self.current_page,
            on_close=lambda: setattr(self, "_guide_popup", None),
        )
        return self._guide_popup

    def _register_guide_target(self, key, widget):
        """Register the real widget a guided-tour step should point to."""
        if widget is not None:
            self.guide_targets[key] = widget

    def get_guide_target(self, key):
        """Return a live target widget for GuidePopup, if the page has it."""
        widget = self.guide_targets.get(key)
        if widget is None:
            return None
        try:
            return widget if widget.winfo_exists() else None
        except tk.TclError:
            return None

    def _tick(self):
        if self._sync_system_theme():
            self.after(1000, self._tick)
            return
        status = self.controller.status()
        settings = status["settings"]
        session = self.controller.auth_session.status(self.username)
        if getattr(self, "sidebar_device_status", None) is not None:
            posture_color = COLORS["green"] if status.get("active") else COLORS["amber"]
            posture_text = "●  Đang bảo vệ" if status.get("active") else "●  Đang chờ cấu hình"
            self.sidebar_device_status.configure(text=posture_text, fg=posture_color)
        if session.get("authenticated"):
            remaining = max(0, int(session["remaining_seconds"]))
            self.session_label.configure(text=f"Auth session: {remaining // 60:02d}:{remaining % 60:02d}", fg=COLORS["green"])
            self.session_meter.configure(bg=COLORS["green"])
            self.session_meter.place_configure(relwidth=min(1, remaining / 900))
        else:
            self.session_label.configure(text="Auth session: cần xác thực", fg=COLORS["amber"])
            self.session_meter.configure(bg=COLORS["amber"])
            self.session_meter.place_configure(relwidth=0)
        marker = (status["label"], settings.get("enabled"), settings.get("pause_until"), status.get("access_locked"))
        if marker != self._last_status_marker:
            self._last_status_marker = marker
            pill = self._page_status_pill
            if pill is not None and pill.winfo_exists():
                pill.configure(bg=status["color"])
                for child in pill.winfo_children():
                    child.configure(bg=status["color"], text=f"●  {status['label']}")
        self._refresh_workflow_details()
        self.after(1000, self._tick)

    def _clear_body(self):
        for child in self.body.winfo_children():
            child.destroy()

    def _header(self, eyebrow, title, subtitle):
        header = tk.Frame(self.body, bg=COLORS["bg"])
        header.pack(fill="x", padx=38, pady=(22, 14))
        breadcrumb = tk.Frame(header, bg=COLORS["bg"])
        breadcrumb.pack(fill="x", pady=(0, 13))
        tk.Label(breadcrumb, text=f"{PRODUCT_NAME.upper()}  /  SECURITY CONSOLE", fg=COLORS["subtle"], bg=COLORS["bg"], font=("Segoe UI", 7, "bold")).pack(side="left")
        tk.Label(breadcrumb, text="LOCAL WINDOWS ENDPOINT", fg=COLORS["cyan"], bg=COLORS["bg"], font=("Segoe UI", 7, "bold")).pack(side="right")
        tk.Frame(header, bg=COLORS["border_soft"], height=1).pack(fill="x", pady=(0, 15))
        left = tk.Frame(header, bg=COLORS["bg"])
        left.pack(side="left")
        title_row = tk.Frame(left, bg=COLORS["bg"])
        title_row.pack(anchor="w")
        tk.Frame(title_row, bg=COLORS["cyan"], width=4, height=34).pack(side="left", fill="y", padx=(0, 12))
        title_text = tk.Frame(title_row, bg=COLORS["bg"])
        title_text.pack(side="left")
        tk.Label(title_text, text=eyebrow.upper(), fg=COLORS["cyan"], bg=COLORS["bg"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(title_text, text=title, fg=COLORS["text"], bg=COLORS["bg"], font=("Segoe UI", 24, "bold")).pack(anchor="w", pady=(2, 1))
        tk.Label(left, text=subtitle, fg=COLORS["muted"], bg=COLORS["bg"], font=("Segoe UI", 9)).pack(anchor="w", padx=(16, 0), pady=(6, 0))
        status = self.controller.status()
        tools = tk.Frame(header, bg=COLORS["bg"])
        tools.pack(side="right", pady=7)
        self._register_guide_target("settings_theme", self._theme_button)
        local_badge = tk.Frame(tools, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        local_badge.pack(side="left", padx=(0, 9))
        tk.Label(local_badge, text="●  LOCAL ONLY", fg=COLORS["green"], bg=COLORS["panel"], font=("Segoe UI", 8, "bold")).pack(padx=10, pady=6)
        make_button(tools, "?  HƯỚNG DẪN", lambda: self.open_guide(self.current_page), bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True).pack(side="left", padx=(0, 10))
        self._page_status_pill = status_pill(tools, status["label"], status["color"])
        self._page_status_pill.pack(side="left")
        self._workflow_bar()

    def _workflow_key(self, page=None):
        return PAGE_WORKFLOW.get(page or self.current_page, "overview")

    def _workflow_index(self, page=None):
        key = self._workflow_key(page)
        return next((index for index, item in enumerate(WORKFLOW_STEPS) if item[0] == key), 0)

    def _workflow_details(self):
        """Build one compact status sentence shared by all workflow views."""
        try:
            status = self.controller.status()
            settings = status["settings"]
            stats = self.controller.db.stats()
            media = self.controller.media_library_state().get("counts", {})
            quarantine = len(self.controller.quarantine.list_items())
            return (
                f"{len(settings.get('include_paths', []))} khu vực bảo vệ",
                f"{media.get('private_vault', 0)} media trong kho riêng",
                f"{stats.get('events', 0)} sự kiện · {stats.get('alerts', 0)} cảnh báo",
                f"{quarantine} mục cách ly",
            )
        except (OSError, RuntimeError, KeyError, TypeError):
            return ("Chưa đọc được phạm vi", "Chưa đọc được chính sách", "Chưa đọc được tín hiệu", "Chưa đọc được cách ly")

    def _open_workflow_step(self, key):
        destination = next((item[3] for item in WORKFLOW_STEPS if item[0] == key), "dashboard")
        if destination == "scope":
            self.open_protected_scope()
        else:
            self.show_page(destination)

    def _workflow_bar(self):
        """Render the same lifecycle navigation on every screen."""
        current = self._workflow_index()
        details = self._workflow_details()
        self._workflow_detail_labels = {}
        bar = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        bar.pack(fill="x", padx=38, pady=(0, 14))
        intro = tk.Frame(bar, bg=COLORS["panel_soft"])
        intro.pack(fill="x", padx=16, pady=(11, 6))
        tk.Label(intro, text="●", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 7))
        tk.Label(intro, text="PROTECTION JOURNEY", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Label(intro, text=f"BƯỚC {current + 1}/{len(WORKFLOW_STEPS)}  ·  {WORKFLOW_STEPS[current][2]}", fg=COLORS["muted"], bg=COLORS["panel_soft"], font=("Segoe UI", 8)).pack(side="right")
        stages = tk.Frame(bar, bg=COLORS["panel_soft"])
        stages.pack(fill="x", padx=10, pady=(0, 10))
        for index, (key, label, _description, _destination) in enumerate(WORKFLOW_STEPS):
            if index:
                connector_color = COLORS["green"] if index <= current else COLORS["border"]
                tk.Frame(stages, bg=connector_color, height=2, width=14).pack(side="left", fill="x", padx=(0, 5))
            stage_bg = COLORS["success_soft"] if index < current else (COLORS["warning_soft"] if index == current else COLORS["panel"])
            if index == current:
                stage_bg = COLORS["info_soft"]
            stage_fg = COLORS["green"] if index < current else (COLORS["cyan"] if index == current else COLORS["muted"])
            stage = tk.Frame(stages, bg=stage_bg, highlightbackground=stage_fg if index == current else COLORS["border"], highlightthickness=1)
            stage.pack(side="left", fill="both", expand=True, padx=(0, 5 if index < len(WORKFLOW_STEPS) - 1 else 0))
            stage_label = f"✓  {label}" if index < current else f"{index + 1}   {label}"
            button = make_button(stage, stage_label, lambda k=key: self._open_workflow_step(k), bg=stage_bg, fg=stage_fg, small=True, outline=True)
            button.pack(fill="x", padx=6, pady=(6, 3))
            self._register_guide_target(f"workflow_{key}", button)
            detail = details[max(0, index - 1)] if index else "Trung tâm điều khiển"
            detail_label = tk.Label(stage, text=detail, fg=COLORS["subtle"], bg=stage_bg, font=("Segoe UI", 7), anchor="w")
            detail_label.pack(fill="x", padx=8, pady=(0, 6))
            self._workflow_detail_labels[index] = detail_label

    def _section_title(self, parent, title, detail=""):
        row = tk.Frame(parent, bg=COLORS["bg"])
        row.pack(fill="x", pady=(0, 10))
        tk.Frame(row, bg=COLORS["cyan"], width=3, height=16).pack(side="left", padx=(0, 8))
        tk.Label(row, text=title, fg=COLORS["text"], bg=COLORS["bg"], font=("Segoe UI", 10, "bold")).pack(side="left")
        if detail:
            tk.Label(row, text=detail, fg=COLORS["subtle"], bg=COLORS["bg"], font=("Segoe UI", 8)).pack(side="right")

    def _card(self, parent, title, value, detail, accent):
        card = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(side="left", fill="both", expand=True, padx=(0, 12))
        tk.Frame(card, bg=accent, height=4).pack(fill="x")
        inner = tk.Frame(card, bg=COLORS["panel"])
        inner.pack(fill="both", expand=True, padx=16, pady=14)
        label_row = tk.Frame(inner, bg=COLORS["panel"])
        label_row.pack(fill="x")
        card_icon = CARD_ICONS.get(title.upper(), "•")
        tk.Label(label_row, text=card_icon, fg=accent, bg=COLORS["panel"], font=("Segoe UI", 11, "bold")).pack(side="left", padx=(0, 7))
        tk.Label(label_row, text=title.upper(), fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Label(inner, text=value, fg=COLORS["text"], bg=COLORS["panel"], font=("Consolas", 23, "bold")).pack(anchor="w", pady=(7, 1))
        tk.Label(inner, text=detail, fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 8)).pack(anchor="w")
        card.bind("<Enter>", lambda _event: card.configure(highlightbackground=accent))
        card.bind("<Leave>", lambda _event: card.configure(highlightbackground=COLORS["border"]))

    def _journey_recommendation(self):
        status = self.controller.status()
        settings = status["settings"]
        stats = self.controller.db.stats()
        quarantine_count = len(self.controller.quarantine.list_items())
        if not settings.get("include_paths"):
            return ("CẤU HÌNH PHẠM VI", "Chưa có thư mục nào được chọn để bảo vệ.", "MỞ KHU VỰC BẢO VỆ", lambda: self.open_protected_scope(), "scope")
        if not settings.get("enabled"):
            return ("BẬT BẢO VỆ", "Phạm vi đã có nhưng giám sát đang tắt.", "BẬT BẢO VỆ", self.toggle_protection, "overview")
        if stats.get("alerts", 0) or quarantine_count:
            return ("XỬ LÝ TÍN HIỆU", "Có cảnh báo hoặc file cách ly cần kiểm tra.", "MỞ CÁCH LY", lambda: self.show_page("quarantine"), "recover")
        return ("ĐẶT CHÍNH SÁCH", "Phạm vi đang được giám sát; chọn chính sách cho tài nguyên nhạy cảm.", "MỞ ACCESS CENTER", lambda: self.show_page("access"), "policy")

    def _journey_board(self):
        title, reason, action_text, command, _key = self._journey_recommendation()
        board = tk.Frame(self.body, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        board.pack(fill="x", padx=38, pady=(0, 17))
        tk.Frame(board, bg=COLORS["cyan"], width=4).pack(side="left", fill="y")
        left = tk.Frame(board, bg=COLORS["panel"])
        left.pack(side="left", fill="both", expand=True, padx=18, pady=15)
        tk.Label(left, text="NEXT SAFE ACTION", fg=COLORS["cyan"], bg=COLORS["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(left, text=title, fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(3, 2))
        tk.Label(left, text=reason, fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 9), anchor="w").pack(anchor="w")
        right = tk.Frame(board, bg=COLORS["panel"])
        right.pack(side="right", padx=18, pady=18)
        make_button(right, action_text, command, bg=COLORS["cyan"], fg=COLORS["bg"], small=True).pack()

    def show_page(self, page):
        self.current_page = page
        # Navigation and the persistent session/help controls survive page
        # swaps.  Every other target belongs to the old page and is discarded
        # before its replacement widgets are built.
        self.guide_targets = {
            key: widget
            for key, widget in self.guide_targets.items()
            if key.startswith("nav_") or key in {"sidebar_help", "sidebar_session"}
        }
        status = self.controller.status()
        settings = status["settings"]
        self._last_status_marker = (status["label"], settings.get("enabled"), settings.get("pause_until"), status.get("access_locked"))
        for key, button in self.nav_buttons.items():
            active = key == page
            button.configure(bg=COLORS["sidebar_active"] if active else COLORS["sidebar"], fg=COLORS["text"] if active else COLORS["muted"])
            indicator = self.nav_indicators.get(key)
            if indicator is not None:
                indicator.configure(bg=COLORS["cyan"] if active else COLORS["sidebar"])
            icon_label = self.nav_icons.get(key)
            if icon_label is not None:
                icon_label.configure(bg=COLORS["sidebar_active"] if active else COLORS["sidebar"], fg=COLORS["cyan"] if active else COLORS["muted"])
        pages = {"dashboard": self._dashboard, "activity": self._activity, "network": self._network, "persistence": self._persistence, "vault": self._vault, "media_library": self._media_library, "scope": self._scope, "media": self._media, "access": self._access_center, "quarantine": self._quarantine, "settings": self._settings}
        root = self._body_root or self.body
        previous = self._visible_page_body
        next_body = tk.Frame(root, bg=COLORS["bg"])
        previous_body = self.body
        self.body = next_body
        try:
            pages[page]()
        finally:
            self.body = previous_body
        next_body.pack(fill="both", expand=True)
        self._bind_context_targets(next_body)
        if previous is not None and previous.winfo_exists():
            previous.pack_forget()
            previous.destroy()
        self._visible_page_body = next_body

    def _dashboard(self):
        self._header("Command center", "Tổng quan bảo vệ", "Theo dõi phạm vi, trạng thái và các tín hiệu bảo mật trên thiết bị này.")
        status = self.controller.status()
        settings = status["settings"]
        stats = self.controller.db.stats()
        posture_color = status["color"]
        hero = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=posture_color, highlightthickness=1)
        hero.pack(fill="x", padx=38, pady=(0, 18))
        tk.Frame(hero, bg=posture_color, width=4).pack(side="left", fill="y")
        self._register_guide_target("dashboard_status", hero)
        left = tk.Frame(hero, bg=COLORS["panel_soft"]); left.pack(side="left", fill="both", expand=True, padx=18, pady=18)
        tk.Label(left, text="PROTECTION POSTURE", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(left, text="Bảo vệ theo phạm vi cấu hình", fg=COLORS["text"], bg=COLORS["panel_soft"], font=("Segoe UI", 15, "bold")).pack(anchor="w", pady=(5, 2))
        detail = "Giám sát đang hoạt động." if status["active"] else "Giám sát đang không hoạt động. Kiểm tra trạng thái bên phải."
        tk.Label(left, text=detail, fg=COLORS["muted"], bg=COLORS["panel_soft"], font=("Segoe UI", 9)).pack(anchor="w")
        right = tk.Frame(hero, bg=COLORS["panel_soft"]); right.pack(side="right", padx=20, pady=18)
        state_badge = tk.Frame(right, bg=posture_color, padx=12, pady=7)
        state_badge.pack(anchor="e")
        tk.Label(state_badge, text=f"●  {status['label']}", fg=COLORS["bg"], bg=posture_color, font=("Segoe UI", 10, "bold")).pack()
        tk.Label(right, text=f"{len(settings['include_paths'])} khu vực • {len(settings['exclude_paths'])} loại trừ", fg=COLORS["muted"], bg=COLORS["panel_soft"], font=("Segoe UI", 8)).pack(anchor="e", pady=(3, 0))
        self._journey_board()
        cards = tk.Frame(self.body, bg=COLORS["bg"]); cards.pack(fill="x", padx=38)
        self._register_guide_target("dashboard_stats", cards)
        self._card(cards, "Khu vực", str(len(settings["include_paths"])), "include đang bảo vệ", COLORS["cyan"])
        self._card(cards, "Sự kiện", str(stats["events"]), "event đã ghi nhận", COLORS["blue"])
        self._card(cards, "Cảnh báo", str(stats["alerts"]), "cảnh báo chưa xử lý", COLORS["amber"])
        self._card(cards, "Quarantine", str(len(self.controller.quarantine.list_items())), "manifest đã tạo", COLORS["purple"])
        self._section_title(self.body, "Thao tác bảo mật", "Mọi thao tác đều yêu cầu mật khẩu")
        actions = tk.Frame(self.body, bg=COLORS["bg"]); actions.pack(fill="x", padx=38, pady=(0, 20))
        self._action_tile(actions, "Bật / tắt bảo vệ", "Thay đổi trạng thái giám sát", self.toggle_protection, COLORS["green"] if not settings.get("enabled") else COLORS["red"], "ON/OFF", "dashboard_toggle")
        self._action_tile(actions, "Tạm dừng giám sát", "Dừng trong khoảng thời gian", lambda: self.pause(15), COLORS["amber"], "PAUSE", "dashboard_pause")
        self._action_tile(actions, "Khóa khu vực", "Khóa quyền vào console bảo vệ", self.lock_protected_access, COLORS["purple"], "LOCK", "dashboard_lock")
        self._action_tile(actions, "Quản lý phạm vi", "Thêm hoặc xóa khu vực", self.open_protected_scope, COLORS["cyan"], "SCOPE")
        self._recent_table(self.body, 7)

    def _action_tile(self, parent, title, detail, command, accent, code, guide_key=None):
        tile = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        tile.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tile.bind("<Enter>", lambda _event: tile.configure(highlightbackground=accent))
        tile.bind("<Leave>", lambda _event: tile.configure(highlightbackground=COLORS["border"]))
        code_row = tk.Frame(tile, bg=COLORS["panel"])
        code_row.pack(fill="x", padx=13, pady=(13, 5))
        chip = tk.Frame(code_row, bg=COLORS["panel_alt"])
        chip.pack(side="left")
        tk.Label(chip, text=code, fg=accent, bg=COLORS["panel_alt"], font=("Segoe UI", 7, "bold")).pack(padx=8, pady=4)
        tk.Label(code_row, text="›", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 13, "bold")).pack(side="right")
        tk.Label(tile, text=title, fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=13)
        tk.Label(tile, text=detail, fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 8), wraplength=150, justify="left").pack(anchor="w", padx=13, pady=(3, 10))
        button = make_button(tile, "MỞ", command, bg=COLORS["panel_alt"], fg=accent, small=True)
        button.pack(anchor="w", padx=13, pady=(0, 12))
        if guide_key:
            self._register_guide_target(guide_key, button)
        return button

    def _recent_table(self, parent, limit):
        frame = tk.Frame(parent, bg=COLORS["bg"]); frame.pack(fill="both", expand=True, padx=38, pady=(0, 24))
        self._section_title(frame, "Hoạt động gần đây", "Mới nhất trước")
        tree, tree_host = self._scrollable_tree(frame, ("time", "type", "path"), height=limit)
        tree.heading("time", text="THỜI GIAN"); tree.heading("type", text="SỰ KIỆN"); tree.heading("path", text="ĐƯỜNG DẪN")
        tree.column("time", width=165); tree.column("type", width=110); tree.column("path", width=620)
        tree_host.pack(fill="both", expand=True)
        target_key = "activity_tree" if self.current_page == "activity" else "dashboard_recent"
        self._register_guide_target(target_key, tree)
        for row in self.controller.db.events(limit):
            tree.insert("", "end", values=(row["timestamp"].replace("T", " ")[:19], row["event_type"], row["path"]))

    def _correlation_banner(self, parent):
        state = self.controller.correlation_state()
        latest = state.get("latest", {})
        active = bool(state.get("active"))
        accent = COLORS["red"] if active else COLORS["green"]
        panel = tk.Frame(parent, bg=COLORS["panel_soft"], highlightbackground=accent, highlightthickness=1)
        panel.pack(fill="x", padx=38, pady=(0, 14))
        header = tk.Frame(panel, bg=COLORS["panel_soft"])
        header.pack(fill="x", padx=16, pady=(12, 3))
        tk.Label(
            header,
            text="DOUBLE-EXTORTION CORRELATION",
            fg=accent,
            bg=COLORS["panel_soft"],
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left")
        status = "ĐANG CẦN XỬ LÝ" if active else "CHƯA GHI NHẬN TƯƠNG QUAN"
        tk.Label(
            header,
            text=f"{status}  ·  {state.get('count', 0)} lần",
            fg=COLORS["muted"],
            bg=COLORS["panel_soft"],
            font=("Segoe UI", 8),
        ).pack(side="right")
        if active:
            text = str(latest.get("message", "Đã phát hiện tương quan file và network cần kiểm tra."))
        else:
            text = (
                "FileSentry đối chiếu hoạt động file với kết nối ngoài trong cửa sổ "
                f"{float(state.get('window_seconds', 120)):.0f} giây. "
                "Đây là chỉ báo cần kiểm tra, không phải kết luận máy đã bị xâm nhập."
            )
        tk.Label(
            panel,
            text=text,
            fg=COLORS["text"],
            bg=COLORS["panel_soft"],
            wraplength=950,
            justify="left",
            anchor="w",
            font=("Segoe UI", 9),
        ).pack(fill="x", padx=16, pady=(0, 10))
        if active:
            actions = tk.Frame(panel, bg=COLORS["panel_soft"])
            actions.pack(fill="x", padx=16, pady=(0, 12))
            network_button = make_button(
                actions,
                "MỞ BẢNG NETWORK",
                lambda: self.show_page("network"),
                bg=COLORS["panel_alt"],
                fg=COLORS["cyan"],
                small=True,
            )
            network_button.pack(side="left")
            quarantine_button = make_button(
                actions,
                "MỞ CÁCH LY",
                lambda: self.show_page("quarantine"),
                bg=COLORS["panel_alt"],
                fg=COLORS["red"],
                small=True,
            )
            quarantine_button.pack(side="left", padx=(8, 0))
            self._register_guide_target("correlation_actions", network_button)

    def _activity(self):
        self._header("Audit stream", "Nhật ký hoạt động", "Event file và network được mã hóa và lưu cục bộ trong SQLite.")
        self._correlation_banner(self.body)
        toolbar = tk.Frame(self.body, bg=COLORS["bg"])
        toolbar.pack(fill="x", padx=38, pady=(0, 8))
        self._section_title(toolbar, "Incident evidence", "xuất báo cáo mã hóa để phân tích")
        export_button = make_button(
            toolbar,
            "XUẤT BÁO CÁO SỰ CỐ",
            self.export_incident_report,
            bg=COLORS["panel_alt"],
            fg=COLORS["cyan"],
            small=True,
        )
        export_button.pack(side="right")
        self._register_guide_target("activity_export", export_button)
        open_button = make_button(
            toolbar,
            "MỞ BÁO CÁO",
            self.open_incident_report,
            bg=COLORS["panel_alt"],
            fg=COLORS["muted"],
            small=True,
        )
        open_button.pack(side="right", padx=(0, 8))
        self._register_guide_target("activity_open_report", open_button)
        self._recent_table(self.body, 19)

    def export_incident_report(self):
        def export():
            hours = simpledialog.askinteger(
                "Khoảng thời gian báo cáo",
                "Lấy dữ liệu trong bao nhiêu giờ gần nhất? (1–720)",
                initialvalue=24,
                minvalue=1,
                maxvalue=720,
                parent=self,
            )
            if hours is None:
                return
            destination = filedialog.asksaveasfilename(
                title="Lưu báo cáo sự cố mã hóa",
                defaultextension=".fsreport",
                filetypes=(("FileSentry encrypted report", "*.fsreport"), ("Encrypted JSON", "*.json")),
            )
            if not destination:
                return
            try:
                result = IncidentReportBuilder(self.controller.db, self.controller).export_encrypted(destination, hours)
                self.controller.db.record_audit(
                    "incident_report_exported",
                    {"path": result["path"], "hours": result["hours"], "username": self.username},
                )
                messagebox.showinfo(
                    "Đã xuất báo cáo",
                    "Báo cáo đã được mã hóa bằng khóa dữ liệu FileSentry và lưu tại vị trí đã chọn.",
                    parent=self,
                )
            except (OSError, ValueError) as exc:
                messagebox.showerror("Không thể xuất báo cáo", str(exc), parent=self)

        self._protected_action(
            "Xuất báo cáo sự cố",
            "Báo cáo gồm timeline event, cảnh báo, audit và posture cục bộ. File xuất được mã hóa; thao tác sẽ ghi audit.",
            export,
        )

    def open_incident_report(self):
        def open_report():
            source = filedialog.askopenfilename(
                title="Mở báo cáo FileSentry",
                filetypes=(("FileSentry encrypted report", "*.fsreport"), ("Encrypted JSON", "*.json")),
            )
            if not source:
                return
            try:
                report, encrypted = self.controller.db.crypto.read_json(Path(source))
                if not encrypted:
                    raise ValueError("Báo cáo phải là file đã mã hóa bởi FileSentry.")
                evidence = report.get("evidence", {})
                integrity = report.get("integrity", {}).get("intrusion_chain", {})
                messagebox.showinfo(
                    "Tóm tắt báo cáo",
                    f"Khoảng thời gian: {report.get('window', {}).get('hours', '?')} giờ\n"
                    f"Events: {evidence.get('events_count', 0)}\n"
                    f"Alerts: {evidence.get('alerts_count', 0)}\n"
                    f"Audit: {evidence.get('audits_count', 0)}\n"
                    f"Hash-chain: {'HỢP LỆ' if integrity.get('valid') else 'CẢNH BÁO'}",
                    parent=self,
                )
                self.controller.db.record_audit("incident_report_opened", {"path": source, "username": self.username})
            except (OSError, ValueError) as exc:
                messagebox.showerror("Không thể mở báo cáo", str(exc), parent=self)

        self._protected_action(
            "Mở báo cáo sự cố",
            "FileSentry sẽ giải mã và chỉ hiển thị bản tóm tắt cục bộ của báo cáo đã mã hóa.",
            open_report,
        )

    def _network(self):
        self._header("Network posture", "Kết nối mạng", "Giám sát thụ động các socket cục bộ và chỉ báo kết nối Internet bất thường.")
        state = self.controller.network_state()
        self._correlation_banner(self.body)
        note = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        note.pack(fill="x", padx=38, pady=(0, 17))
        tk.Label(note, text="LOCAL-ONLY NETWORK TELEMETRY", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(13, 4))
        tk.Label(note, text="FileSentry chỉ đọc bảng kết nối của Windows, không quét cổng, không phân giải DNS, không gửi địa chỉ IP ra ngoài và không tự chặn kết nối trong V1. Chỉ báo không đồng nghĩa với kết luận máy đã bị xâm nhập.", fg=COLORS["muted"], bg=COLORS["panel_soft"], wraplength=920, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(0, 13))
        cards = tk.Frame(self.body, bg=COLORS["bg"]); cards.pack(fill="x", padx=38, pady=(0, 16))
        self._card(cards, "Socket", str(state.get("connection_count", 0)), "kết nối hiện tại", COLORS["cyan"])
        self._card(cards, "Internet", str(state.get("external_count", 0)), "kết nối tới IP public", COLORS["blue"])
        self._card(cards, "Backend", state.get("backend", "unavailable"), "nguồn dữ liệu cục bộ", COLORS["green"])
        last_scan = state.get("last_scan")
        scan_text = datetime.fromtimestamp(last_scan).strftime("%H:%M:%S") if last_scan else "chưa quét"
        self._card(cards, "Lần quét", scan_text, "thời gian gần nhất", COLORS["purple"])
        toolbar = tk.Frame(self.body, bg=COLORS["bg"]); toolbar.pack(fill="x", padx=38, pady=(0, 8))
        self._section_title(toolbar, "Bảng kết nối", "chỉ đọc")
        refresh_button = make_button(toolbar, "LÀM MỚI", lambda: (self.controller.network.scan_once(), self.show_page("network")), bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True)
        refresh_button.pack(side="right")
        if state.get("last_error"):
            tk.Label(self.body, text=state["last_error"], fg=COLORS["red"], bg=COLORS["bg"], font=("Segoe UI", 8)).pack(anchor="w", padx=38, pady=(0, 8))
        frame = tk.Frame(self.body, bg=COLORS["bg"]); frame.pack(fill="both", expand=True, padx=38, pady=(0, 24))
        tree, tree_host = self._scrollable_tree(frame, ("protocol", "process", "pid", "local", "remote", "status", "risk"))
        self._register_guide_target("network_tree", tree)
        for column, label, width in (("protocol", "PROTO", 70), ("process", "PROCESS", 150), ("pid", "PID", 75), ("local", "LOCAL", 180), ("remote", "REMOTE", 210), ("status", "STATUS", 115), ("risk", "INDICATOR", 330)):
            tree.heading(column, text=label); tree.column(column, width=width)
        tree_host.pack(fill="both", expand=True)
        for row in state.get("connections", []):
            local = f"{row.get('local_address')}:{row.get('local_port')}"
            remote = f"{row.get('remote_address')}:{row.get('remote_port')}" if row.get("remote_address") else "-"
            risk = "; ".join(item.get("title", "") for item in row.get("risk", [])) or "—"
            tree.insert("", "end", values=(row.get("protocol"), row.get("process_name"), row.get("pid") or "-", local, remote, row.get("status") or "UDP", risk))

    def _vault(self):
        self._header("Encrypted storage", "Kho mã hóa", "Lưu bản mã hóa theo từng file/chunk; đây là vault lưu trữ, không phải khóa thư mục real-time.")
        note = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        note.pack(fill="x", padx=38, pady=(0, 17))
        tk.Label(note, text="AEAD ENCRYPTED VAULT", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(13, 4))
        tk.Label(note, text="File gốc không bị xóa khi đưa vào vault. Bản lưu trong kho được mã hóa theo chunk, có hash kiểm tra khi khôi phục. Muốn bảo vệ mọi thao tác Explorer cần Filesystem Minifilter ở V2.", fg=COLORS["muted"], bg=COLORS["panel_soft"], wraplength=920, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(0, 13))
        frame = tk.Frame(self.body, bg=COLORS["bg"]); frame.pack(fill="both", expand=True, padx=38, pady=(0, 24))
        toolbar = tk.Frame(frame, bg=COLORS["bg"]); toolbar.pack(fill="x", pady=(0, 9))
        self._section_title(toolbar, "Vault inventory", "khôi phục không ghi đè")
        import_button = make_button(toolbar, "+ ĐƯA FILE VÀO VAULT", self.vault_import, bg=COLORS["cyan"], fg=COLORS["bg"], small=True)
        import_button.pack(side="right")
        self._register_guide_target("vault_import", import_button)
        tree, tree_host = self._scrollable_tree(frame, ("id", "created", "source", "size", "status"))
        self._register_guide_target("vault_tree", tree)
        for column, label, width in (("id", "ID", 110), ("created", "THỜI GIAN", 175), ("source", "FILE GỐC", 520), ("size", "BYTES", 100), ("status", "TRẠNG THÁI", 115)):
            tree.heading(column, text=label); tree.column(column, width=width)
        tree_host.pack(fill="both", expand=True)
        items = self.controller.vault.list_items()
        for item in items:
            status = "KHÔNG XUẤT" if item.get("export_blocked") else item.get("status", "")
            tree.insert("", "end", iid=item["id"], values=(item["id"][:10], item.get("created_at", "")[:19].replace("T", " "), item.get("original_path", ""), item.get("size", ""), status))
        actions = tk.Frame(frame, bg=COLORS["bg"]); actions.pack(fill="x", pady=(12, 0))
        restore_button = make_button(actions, "KHÔI PHỤC MỤC ĐANG CHỌN", lambda: self.vault_restore(tree), bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True)
        restore_button.pack(side="right")
        self._register_guide_target("vault_restore", restore_button)

    def _media_library(self):
        self._header("Media privacy", "Ảnh / Video / Âm thanh", "Quản lý file media, khóa xóa và đưa dữ liệu riêng vào kho mã hóa.")
        state = self.controller.media_library_state()
        counts = state.get("counts", {})
        note = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        note.pack(fill="x", padx=38, pady=(0, 16))
        tk.Label(note, text="MEDIA PROTECTION", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(13, 4))
        tk.Label(note, text="Đồng bộ toàn bộ các ổ đĩa cục bộ để tự thêm media mới, cập nhật file đã thay đổi và đánh dấu file đã xóa hoặc di chuyển. File thường có thể được khóa xóa ở mức Windows; muốn chặn đọc, sao chép hoặc gửi ra ngoài ở mức mạnh nhất, hãy đưa file vào Kho riêng mã hóa.", fg=COLORS["muted"], bg=COLORS["panel_soft"], wraplength=980, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=17, pady=(0, 12))
        summary = tk.Frame(self.body, bg=COLORS["bg"])
        summary.pack(fill="x", padx=38, pady=(0, 12))
        self._card(summary, "Ảnh", str(counts.get("image", 0)), "mục đang quản lý", COLORS["purple"])
        self._card(summary, "Video", str(counts.get("video", 0)), "mục đang quản lý", COLORS["cyan"])
        self._card(summary, "Âm thanh", str(counts.get("audio", 0)), "mục đang quản lý", COLORS["blue"])
        self._card(summary, "Kho riêng", str(counts.get("private_vault", 0)), "không có file thường bên ngoài", COLORS["green"])
        toolbar = tk.Frame(self.body, bg=COLORS["bg"])
        toolbar.pack(fill="x", padx=38, pady=(0, 8))
        self._section_title(toolbar, "Media inventory", f"{len(state.get('items', []))} mục · {counts.get('missing', 0)} đã rời máy")
        sync_button = make_button(toolbar, "ĐỒNG BỘ TOÀN BỘ MÁY", self.scan_media_library, bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True)
        sync_button.pack(side="right")
        self._register_guide_target("media_sync", sync_button)
        add_button = make_button(toolbar, "+ THÊM FILE MEDIA", self.add_media_file, bg=COLORS["cyan"], fg=COLORS["bg"], small=True)
        add_button.pack(side="right", padx=(0, 8))
        self._register_guide_target("media_add", add_button)
        clear_button = make_button(toolbar, "XÓA SẠCH DANH SÁCH (GIỮ FILE)", self.clear_media_library_inventory, bg=COLORS["panel_alt"], fg=COLORS["red"], small=True)
        clear_button.pack(side="right", padx=(0, 8))
        self._register_guide_target("media_clear", clear_button)
        frame = tk.Frame(self.body, bg=COLORS["bg"])
        frame.pack(fill="both", expand=True, padx=38, pady=(0, 24))
        tree, tree_host = self._scrollable_tree(frame, ("type", "name", "location", "status", "delete", "export"))
        self.media_library_tree = tree
        self._register_guide_target("media_tree", tree)
        for column, label, width in (("type", "LOẠI", 90), ("name", "TÊN FILE", 205), ("location", "VỊ TRÍ", 410), ("status", "LƯU TRỮ", 135), ("delete", "XÓA", 110), ("export", "GỬI RA NGOÀI", 135)):
            tree.heading(column, text=label)
            tree.column(column, width=width)
        tree_host.pack(fill="both", expand=True)
        type_labels = {"image": "ẢNH", "video": "VIDEO", "audio": "ÂM THANH"}
        for item in state.get("items", []):
            private = item.get("storage_mode") == "private_vault"
            missing = bool(item.get("missing") or not item.get("present", item.get("exists", False)))
            tree.insert(
                "",
                "end",
                iid=item["id"],
                values=(
                    type_labels.get(item.get("media_type"), "MEDIA"),
                    item.get("name", ""),
                    item.get("path", "") if not private and not missing else ("Đã xóa hoặc di chuyển" if missing else "Kho riêng mã hóa"),
                    "KHO RIÊNG" if private else ("ĐÃ RỜI KHỎI MÁY" if missing else "FILE NGOÀI"),
                    "KHÔNG XÓA" if item.get("delete_protected") else "CHO PHÉP",
                    "KHÔNG XUẤT" if item.get("export_protected") else "CHO PHÉP",
                ),
            )
        actions = tk.Frame(frame, bg=COLORS["bg"])
        actions.pack(fill="x", pady=(10, 0))
        view_button = make_button(actions, "XEM / MỞ MEDIA ĐÃ CHỌN", self.view_selected_media, bg=COLORS["cyan"], fg=COLORS["bg"], small=True)
        view_button.pack(side="left")
        self._register_guide_target("media_view", view_button)
        protect_button = make_button(actions, "KHÓA XÓA FILE", self.protect_selected_media, bg=COLORS["panel_alt"], fg=COLORS["amber"], small=True)
        protect_button.pack(side="left")
        self._register_guide_target("media_protect", protect_button)
        secure_button = make_button(actions, "CHỐNG GỬI RA NGOÀI", self.secure_selected_media, bg=COLORS["green"], fg=COLORS["bg"], small=True)
        secure_button.pack(side="left", padx=8)
        self._register_guide_target("media_secure", secure_button)
        remove_button = make_button(actions, "GỠ BẢO VỆ FILE", self.remove_selected_media_policy, bg=COLORS["panel_alt"], fg=COLORS["red"], small=True)
        remove_button.pack(side="right")
        self._register_guide_target("media_remove", remove_button)

    def _selected_media_item(self):
        tree = getattr(self, "media_library_tree", None)
        selected = tree.selection() if tree else []
        if not selected:
            messagebox.showinfo("Chưa chọn file", "Hãy chọn một ảnh, video hoặc file âm thanh.", parent=self)
            return None
        item_id = selected[0]
        return next((item for item in self.controller.media_library_state().get("items", []) if item.get("id") == item_id), None)

    def clear_media_library_inventory(self):
        def clear():
            if not messagebox.askyesno(
                "Xóa danh sách media",
                "FileSentry sẽ xóa các mục file ngoài khỏi danh sách quản lý, nhưng không xóa nội dung ảnh, video hoặc MP3 trên ổ đĩa. ACL do FileSentry thêm sẽ được gỡ để không tạo khóa mồ côi. Các mục trong Kho riêng sẽ được giữ lại.",
                icon="warning",
                parent=self,
            ):
                return
            try:
                result = self.controller.clear_media_library_inventory(self.username)
                failures = len(result.get("failures", []))
                skipped = len(result.get("skipped_private_vault", []))
                message = f"Đã xóa {len(result.get('cleared', []))} mục khỏi danh sách; file thật không bị xóa."
                if skipped:
                    message += f" Giữ lại {skipped} mục Kho riêng để tránh làm mồ côi dữ liệu mã hóa."
                if failures:
                    message += f" {failures} mục chưa xóa do không gỡ được ACL."
                self.toast("Đã làm sạch Media Library", message, "success" if not failures else "warning")
                self.show_page("media_library")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể xóa danh sách media", str(exc), parent=self)
        self._protected_action("Xóa danh sách media", "Chỉ xóa inventory trong FileSentry; không xóa file thật. Thao tác sẽ dọn ACL do FileSentry sở hữu để không để lại khóa mồ côi.", clear, force_reauth=True)

    def view_selected_media(self):
        item = self._selected_media_item()
        if not item:
            return
        if item.get("missing") or not item.get("present", item.get("exists", False)):
            messagebox.showinfo("File không còn trên máy", "Mục này chỉ còn lịch sử trong FileSentry vì file đã bị xóa hoặc di chuyển.", parent=self)
            return

        def open_media():
            try:
                resource = self.controller.open_media_item(item["id"], self.username)
                if resource.get("media_type") == "image":
                    self._show_image_preview(resource)
                    return
                if resource.get("storage_mode") == "private_vault":
                    messagebox.showinfo("Không tạo file ngoài", "Video và âm thanh trong Kho riêng không được tạo thành file thường bên ngoài. Hãy dùng thao tác khôi phục được xác thực nếu chính sách cho phép.", parent=self)
                    return
                if os.name == "nt":
                    os.startfile(resource["path"])
                else:
                    raise OSError("Mở media bằng ứng dụng mặc định chỉ hỗ trợ trên Windows.")
                self.toast("Đã mở media", "File được mở bằng ứng dụng mặc định của Windows; FileSentry không chỉnh sửa file.", "success")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể xem media", str(exc), parent=self)
        self._protected_action("Xem media", "Mở ảnh trong cửa sổ xem trước của FileSentry hoặc mở video/âm thanh bằng ứng dụng mặc định, không tạo bản sao và không sửa file.", open_media)

    def _show_image_preview(self, resource: dict):
        if Image is None or ImageTk is None:
            if resource.get("storage_mode") == "external" and os.name == "nt":
                os.startfile(resource["path"])
                return
            raise RuntimeError("Chưa có thành phần xem ảnh trong bản cài đặt này.")
        try:
            if resource.get("storage_mode") == "private_vault":
                image = Image.open(io.BytesIO(resource["bytes"]))
            else:
                image = Image.open(resource["path"])
            image.load()
            image.thumbnail((1100, 700), Image.Resampling.LANCZOS)
        except Exception as exc:
            raise RuntimeError("Không đọc được ảnh để xem trước an toàn.") from exc
        preview = tk.Toplevel(self)
        preview.title(f"Xem ảnh — {resource.get('name', '')}")
        preview.geometry("980x700")
        preview.configure(bg=COLORS["bg"])
        canvas_host = tk.Frame(preview, bg=COLORS["bg"])
        canvas_host.pack(fill="both", expand=True, padx=18, pady=18)
        canvas = tk.Canvas(canvas_host, bg=COLORS["bg"], highlightthickness=0)
        vertical = ttk.Scrollbar(canvas_host, orient="vertical", command=canvas.yview)
        horizontal = ttk.Scrollbar(canvas_host, orient="horizontal", command=canvas.xview)
        canvas.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        canvas_host.grid_rowconfigure(0, weight=1); canvas_host.grid_columnconfigure(0, weight=1)
        photo = ImageTk.PhotoImage(image)
        canvas.create_image(0, 0, anchor="nw", image=photo)
        canvas.image = photo
        canvas.configure(scrollregion=(0, 0, image.width, image.height))

    def scan_media_library(self):
        if self._media_scan_running:
            self.toast("Đang đồng bộ", "Media Library đang được xử lý ở nền. Bạn có thể tiếp tục dùng các màn hình khác.", "info")
            return

        dialog = tk.Toplevel(self)
        dialog.title("Đồng bộ Media Library")
        dialog.geometry("650x285")
        dialog.resizable(False, False)
        dialog.configure(bg=COLORS["panel"])
        dialog.transient(self)
        dialog.protocol("WM_DELETE_WINDOW", lambda: cancel_scan())
        self._media_scan_dialog = dialog
        self._register_guide_target("media_scan_dialog", dialog)
        self._media_scan_running = True
        cancel_event = Event()
        self._media_scan_cancel = cancel_event
        started_at = datetime.now()

        tk.Label(dialog, text="MEDIA LIBRARY SYNC", fg=COLORS["cyan"], bg=COLORS["panel"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=28, pady=(25, 5))
        title = tk.Label(dialog, text="Đang chuẩn bị đồng bộ toàn bộ máy…", fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 14, "bold"))
        title.pack(anchor="w", padx=28)
        detail = tk.Label(dialog, text="Giao diện vẫn hoạt động bình thường; bạn có thể thu nhỏ cửa sổ này.", fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 9), anchor="w", justify="left", wraplength=590)
        detail.pack(fill="x", padx=28, pady=(7, 17))
        progress = ttk.Progressbar(dialog, orient="horizontal", mode="determinate", maximum=100, value=0)
        progress.pack(fill="x", padx=28)
        self._register_guide_target("media_scan_progress", progress)
        stats = tk.Label(dialog, text="Đã phát hiện 0 file media", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 9), anchor="w")
        stats.pack(fill="x", padx=28, pady=(8, 0))

        def cancel_scan():
            if not cancel_event.is_set():
                cancel_event.set()
                cancel_button.configure(text="ĐANG HỦY…", state="disabled")
                title.configure(text="Đang hủy đồng bộ…")
                detail.configure(text="Không đánh dấu nhầm các file chưa kịp kiểm tra.")

        footer = tk.Frame(dialog, bg=COLORS["panel"])
        footer.pack(fill="x", padx=28, pady=(18, 22))
        cancel_button = make_button(footer, "HỦY ĐỒNG BỘ", cancel_scan, bg=COLORS["panel_alt"], fg=COLORS["amber"], small=True)
        cancel_button.pack(side="right")

        def format_eta(seconds: float | None) -> str:
            if seconds is None or seconds < 1:
                return "đang ước tính thời gian còn lại"
            seconds = int(seconds)
            if seconds < 60:
                return f"còn khoảng {seconds}s"
            return f"còn khoảng {seconds // 60}m {seconds % 60:02d}s"

        def update_progress(info: dict):
            if not dialog.winfo_exists():
                return
            phase = info.get("phase")
            discovered = info.get("discovered", 0)
            processed = info.get("processed", 0)
            total = info.get("total")
            percent = info.get("percent")
            if percent is not None:
                progress.configure(value=percent)
            if phase == "discovering":
                title.configure(text="Đang lập danh sách file media…")
                detail.configure(text="Đang đi qua các ổ đĩa cục bộ và bỏ qua vùng hệ thống/cache.")
                stats.configure(text=f"Đã phát hiện {discovered:,} file media · đang quét ổ đĩa")
            elif phase == "processing":
                title.configure(text="Đang cập nhật Media Library…")
                elapsed = max((datetime.now() - started_at).total_seconds(), 0.1)
                eta = elapsed * (total - processed) / processed if total and processed else None
                detail.configure(text=f"Đã đồng bộ {processed:,}/{total or 0:,} file · {percent or 0}% · {format_eta(eta)}")
                stats.configure(text=f"File hiện tại: {Path(info.get('current', '')).name or 'đang xử lý'}")
            elif phase == "cancelled":
                title.configure(text="Đã yêu cầu hủy đồng bộ")
                detail.configure(text="Đang hoàn tất phần an toàn còn lại…")
                cancel_button.configure(state="disabled")

        def finish(result=None, error=None):
            self._media_scan_running = False
            self._media_scan_cancel = None
            if dialog.winfo_exists():
                dialog.destroy()
            self._media_scan_dialog = None
            if error is not None:
                messagebox.showerror("Không thể đồng bộ media", str(error), parent=self)
                return
            if result and result.get("cancelled"):
                self.toast("Đã hủy đồng bộ", "Các file chưa kiểm tra không bị đánh dấu nhầm là đã rời máy.", "warning")
                self.show_page("media_library")
                return
            self.toast(
                "Đã đồng bộ toàn bộ máy",
                f"Đã kiểm tra {result.get('scanned', 0)} file · thêm {result.get('registered', 0)} · cập nhật {result.get('updated', 0)} · rời máy {result.get('removed', 0)}.",
                "success",
            )
            self.show_page("media_library")

        def worker():
            try:
                result = self.controller.scan_media_library(
                    self.username,
                    full_machine=True,
                    progress_callback=lambda info: self.after(0, lambda value=info: update_progress(value)),
                    cancel_event=cancel_event,
                )
                self.after(0, lambda: finish(result=result))
            except Exception as exc:
                self.after(0, lambda error=exc: finish(error=error))

        Thread(target=worker, name="FileSentryMediaSync", daemon=True).start()

    def add_media_file(self):
        def choose():
            path = filedialog.askopenfilename(
                title="Chọn ảnh, video hoặc âm thanh",
                filetypes=[
                    ("Media", "*.jpg *.jpeg *.png *.gif *.bmp *.webp *.mp4 *.mov *.avi *.mkv *.mp3 *.wav *.flac *.m4a *.ogg"),
                    ("Tất cả file", "*.*"),
                ],
            )
            if not path:
                return
            try:
                item = self.controller.register_media_file(path, self.username)
                if messagebox.askyesno("Không cho phép xóa", "Khóa xóa file này ở mức Windows?", parent=self):
                    self.controller.set_media_file_policy(item["id"], delete_protected=True, username=self.username)
                if messagebox.askyesno("Không cho phép gửi ra ngoài", "Đưa file vào Kho riêng mã hóa? Bản file thường bên ngoài sẽ được xóa sau khi mã hóa thành công.", parent=self):
                    self.controller.secure_media_file(item["id"], self.username)
                self.toast("Đã thêm file media", "Chính sách bảo vệ đã được lưu.", "success")
                self.show_page("media_library")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể quản lý file media", str(exc), parent=self)
        self._protected_action("Thêm file media", "FileSentry sẽ lưu metadata được mã hóa và cho phép bạn chọn khóa xóa hoặc đưa file vào Kho riêng.", choose, force_reauth=True)

    def protect_selected_media(self):
        item = self._selected_media_item()
        if not item:
            return
        if item.get("storage_mode") == "private_vault":
            messagebox.showinfo("Đã ở Kho riêng", "File trong Kho riêng đã được bảo vệ khỏi thao tác bên ngoài.", parent=self)
            return
        def apply():
            if not messagebox.askyesno("Xác nhận khóa xóa", "Không cho phép xóa hoặc đổi tên file này từ Windows?", parent=self):
                return
            try:
                self.controller.set_media_file_policy(item["id"], delete_protected=True, username=self.username)
                self.toast("Đã khóa xóa file", "File vẫn có thể mở, nhưng thao tác xóa/đổi tên sẽ bị từ chối.", "success")
                self.show_page("media_library")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể khóa xóa", str(exc), parent=self)
        self._protected_action("Khóa xóa file media", "FileSentry sẽ áp dụng khóa xóa riêng cho file đã chọn.", apply, force_reauth=True)

    def secure_selected_media(self):
        item = self._selected_media_item()
        if not item:
            return
        if item.get("storage_mode") == "private_vault":
            messagebox.showinfo("Đã ở Kho riêng", "File này đã ở chế độ không xuất.", parent=self)
            return
        def apply():
            if not messagebox.askyesno("Đưa vào Kho riêng", "File sẽ được mã hóa trong FileSentry và bản file thường bên ngoài sẽ bị xóa sau khi mã hóa thành công. Tiếp tục?", parent=self):
                return
            try:
                self.controller.secure_media_file(item["id"], self.username)
                self.toast("Đã đưa vào Kho riêng", "File không còn ở dạng đọc được bên ngoài FileSentry.", "success")
                self.show_page("media_library")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể đưa vào Kho riêng", str(exc), parent=self)
        self._protected_action("Chống gửi media ra ngoài", "Kho riêng mã hóa là chế độ duy nhất có thể chặn việc đọc và sao chép file thường từ ứng dụng bên ngoài.", apply, force_reauth=True)

    def remove_selected_media_policy(self):
        item = self._selected_media_item()
        if not item:
            return
        if item.get("storage_mode") == "private_vault":
            messagebox.showinfo("Không có file ngoài", "File trong Kho riêng không có bản file thường để gỡ khóa.", parent=self)
            return
        def remove():
            if not messagebox.askyesno("Gỡ chính sách", "Cho phép lại thao tác xóa file này từ Windows?", parent=self):
                return
            try:
                self.controller.remove_media_file_policy(item["id"], self.username)
                self.toast("Đã gỡ chính sách", "File trở về quyền thông thường của Windows.", "warning")
                self.show_page("media_library")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể gỡ chính sách", str(exc), parent=self)
        self._protected_action("Gỡ bảo vệ file media", "Thao tác này cho phép xóa hoặc đổi tên file trở lại.", remove, force_reauth=True)

    def _persistence(self):
        self._header("Endpoint posture", "Startup & Persistence", "Theo dõi read-only Run key, Startup folder, Scheduled Task và Service.")
        state = self.controller.persistence_state()
        note = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        note.pack(fill="x", padx=38, pady=(0, 17))
        tk.Label(note, text="READ-ONLY PERSISTENCE INVENTORY", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(13, 4))
        tk.Label(note, text="FileSentry không tự xóa Registry, Task hoặc Service. Chỉ báo persistence mới cần được đối chiếu với phần mềm bạn đã cài; thay đổi cấu hình yêu cầu thao tác riêng có xác nhận.", fg=COLORS["muted"], bg=COLORS["panel_soft"], wraplength=920, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(0, 13))
        toolbar = tk.Frame(self.body, bg=COLORS["bg"]); toolbar.pack(fill="x", padx=38, pady=(0, 8))
        self._section_title(toolbar, "Persistence inventory", f"{state.get('count', 0)} mục • {state.get('backend', 'unavailable')}")
        refresh_button = make_button(toolbar, "LÀM MỚI", lambda: (self.controller.persistence.scan_once(), self.show_page("persistence")), bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True)
        refresh_button.pack(side="right")
        if state.get("last_error"):
            tk.Label(self.body, text=state["last_error"], fg=COLORS["red"], bg=COLORS["bg"], font=("Segoe UI", 8)).pack(anchor="w", padx=38, pady=(0, 8))
        frame = tk.Frame(self.body, bg=COLORS["bg"]); frame.pack(fill="both", expand=True, padx=38, pady=(0, 24))
        tree, tree_host = self._scrollable_tree(frame, ("kind", "name", "command", "location", "risk"))
        self._register_guide_target("persistence_tree", tree)
        for column, label, width in (("kind", "TYPE", 145), ("name", "NAME", 280), ("command", "COMMAND", 360), ("location", "LOCATION", 260), ("risk", "INDICATOR", 300)):
            tree.heading(column, text=label); tree.column(column, width=width)
        tree_host.pack(fill="both", expand=True)
        for entry in state.get("entries", []):
            risk = "; ".join(item.get("title", "") for item in entry.get("risks", [])) or "—"
            tree.insert("", "end", values=(entry.get("kind"), entry.get("name"), entry.get("command"), entry.get("location"), risk))

    def vault_import(self):
        def import_file():
            source = filedialog.askopenfilename(title="Chọn file đưa vào vault")
            if not source:
                return
            try:
                self.controller.unlock_vault_session(self.username)
                item = self.controller.vault.import_file(source)
                self.controller.db.record_audit("vault_file_imported", {"id": item["id"], "username": self.username})
                self.show_page("vault")
            except (OSError, ValueError) as exc:
                messagebox.showerror("Không thể đưa file vào vault", str(exc), parent=self)
        self._protected_action("Đưa file vào kho mã hóa", "File gốc được giữ nguyên; FileSentry tạo thêm một bản mã hóa trong vault.", import_file, force_reauth=True)

    def open_vault_page(self):
        def enter_vault():
            try:
                self.controller.unlock_vault_session(self.username)
                self.show_page("vault")
            except (OSError, ValueError) as exc:
                messagebox.showerror("Không thể mở vault", str(exc), parent=self)
        self._protected_action(
            "Mở kho mã hóa",
            "FileSentry sẽ tạo một phiên Vault tạm thời trong bộ nhớ trước khi hiển thị inventory và cho phép thao tác file.",
            enter_vault,
            force_reauth=True,
        )

    def vault_restore(self, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Chưa chọn", "Hãy chọn một mục trong vault.", parent=self)
            return
        item_id = selected[0]
        item = next((value for value in self.controller.vault.list_items() if value.get("id") == item_id), None)
        initial_name = Path(item.get("original_path", "restored-file" )).name if item else "restored-file"
        def restore_file():
            destination = filedialog.asksaveasfilename(title="Chọn nơi khôi phục file", initialfile=initial_name)
            if not destination:
                return
            try:
                self.controller.unlock_vault_session(self.username)
                self.controller.vault.restore(item_id, destination)
                self.controller.db.record_audit("vault_file_restored", {"id": item_id, "username": self.username})
                messagebox.showinfo("Đã khôi phục", "File đã được giải mã và khôi phục. Bản trong vault vẫn được giữ lại.", parent=self)
                self.show_page("vault")
            except (OSError, ValueError) as exc:
                messagebox.showerror("Không thể khôi phục vault", str(exc), parent=self)
        self._protected_action("Khôi phục file từ vault", "File đích không được tồn tại; FileSentry không tự ghi đè dữ liệu.", restore_file, force_reauth=True)

    def _access_center(self):
        self._header("App-gated resources", "Access Center", "Một phiên mở khóa ngắn hạn cho tài nguyên nhạy cảm; token chỉ tồn tại trong bộ nhớ.")
        note = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        note.pack(fill="x", padx=38, pady=(0, 17))
        tk.Label(note, text="WATCH & REVERT MODEL", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(13, 4))
        tk.Label(note, text="Camera/Mic được theo dõi định kỳ. Nếu tài nguyên đang được FileSentry quản lý mà bị mở ngoài phiên xác thực, ứng dụng sẽ áp dụng Deny lại và ghi cảnh báo. Đây không phải pre-hook tuyệt đối của Windows.", fg=COLORS["muted"], bg=COLORS["panel_soft"], wraplength=920, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(0, 13))
        hub = tk.Frame(self.body, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        hub.pack(fill="x", padx=38, pady=(0, 17))
        tk.Label(hub, text="CHỌN TÀI NGUYÊN TRONG CÙNG LUỒNG CHÍNH SÁCH", fg=COLORS["cyan"], bg=COLORS["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(12, 8))
        hub_actions = tk.Frame(hub, bg=COLORS["panel"])
        hub_actions.pack(fill="x", padx=17, pady=(0, 13))
        make_button(hub_actions, "CAMERA & MICROPHONE", lambda: self.show_page("media"), bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True).pack(side="left")
        make_button(hub_actions, "MEDIA LIBRARY", lambda: self.show_page("media_library"), bg=COLORS["panel_alt"], fg=COLORS["purple"], small=True).pack(side="left", padx=7)
        make_button(hub_actions, "KHO MÃ HÓA", self.open_vault_page, bg=COLORS["panel_alt"], fg=COLORS["green"], small=True).pack(side="left")
        make_button(hub_actions, "KHU VỰC BẢO VỆ", self.open_protected_scope, bg=COLORS["panel_alt"], fg=COLORS["amber"], small=True).pack(side="right")
        cards = tk.Frame(self.body, bg=COLORS["bg"])
        cards.pack(fill="x", padx=38, pady=(0, 18))
        for kind, title, accent in (("camera", "Camera", COLORS["purple"]), ("microphone", "Microphone", COLORS["cyan"])):
            state = self.controller.media_state(kind)
            session = state.get("unlock_session", {})
            remaining = int(session.get("remaining_seconds", 0))
            if session.get("unlocked"):
                status_text = f"ĐANG MỞ — còn {remaining // 60} phút"
                status_color = COLORS["green"]
            elif state.get("system_deny"):
                status_text = "ĐANG KHÓA"
                status_color = COLORS["red"]
            else:
                status_text = "CHƯA QUẢN LÝ"
                status_color = COLORS["amber"]
            card = tk.Frame(cards, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 14))
            tk.Frame(card, bg=accent, height=4).pack(fill="x")
            tk.Label(card, text=title, fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=17, pady=(14, 2))
            tk.Label(card, text="●  " + status_text, fg=status_color, bg=COLORS["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(0, 13))
            actions = tk.Frame(card, bg=COLORS["panel"]); actions.pack(fill="x", padx=17, pady=(0, 16))
            unlock_button = make_button(actions, "MỞ KHÓA 30 PHÚT", lambda k=kind: self.media_unlock(k), bg=COLORS["green"], fg=COLORS["bg"], small=True)
            unlock_button.pack(side="left")
            lock_button = make_button(actions, "KHÓA LẠI", lambda k=kind: self.media_lock(k), bg=COLORS["panel_alt"], fg=COLORS["red"], small=True)
            lock_button.pack(side="left", padx=7)
            if kind == "camera":
                self._register_guide_target("access_camera_unlock", unlock_button)
                self._register_guide_target("access_camera_lock", lock_button)
        vault = self.controller.vault.list_items()
        vault_session = self.controller.access_state("vault")
        vault_status = "PHIÊN ĐANG MỞ" if vault_session.get("unlocked") else "ĐANG KHÓA"
        vault_status_color = COLORS["green"] if vault_session.get("unlocked") else COLORS["red"]
        vault_panel = tk.Frame(self.body, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        vault_panel.pack(fill="x", padx=38, pady=(0, 18))
        tk.Label(vault_panel, text="Vault storage", fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=17, pady=(14, 3))
        tk.Label(vault_panel, text="●  " + vault_status, fg=vault_status_color, bg=COLORS["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(0, 4))
        tk.Label(vault_panel, text=f"{len(vault)} mục đang lưu. Vault V1 không mount thành ổ đĩa; mỗi file được mã hóa và chỉ giải mã qua thao tác khôi phục có xác thực.", fg=COLORS["muted"], bg=COLORS["panel"], wraplength=920, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(0, 13))
        vault_button = make_button(vault_panel, "MỞ KHO MÃ HÓA", self.open_vault_page, bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True)
        vault_button.pack(anchor="w", padx=17, pady=(0, 15))
        self._register_guide_target("access_vault", vault_button)

    def _media(self):
        self._header("Privacy control", "Camera & Microphone Guard", "Kiểm soát quyền camera/microphone ở mức Windows và quản lý origin được phép.")
        note = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        note.pack(fill="x", padx=38, pady=(0, 17))
        tk.Label(note, text="SYSTEM-LEVEL PRIVACY", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(13, 4))
        tk.Label(note, text="Khóa toàn bộ sẽ dùng Windows App Privacy Policy và quyền desktop app, có thể yêu cầu quyền Administrator. Website allowlist hiện được lưu làm policy cho browser extension; Windows không tự phân biệt URL bên trong browser.", fg=COLORS["muted"], bg=COLORS["panel_soft"], wraplength=900, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(0, 13))
        row = tk.Frame(self.body, bg=COLORS["bg"]); row.pack(fill="both", expand=True, padx=38)
        self._media_card(row, "camera", "Camera", "ms-settings:privacy-webcam", COLORS["purple"])
        self._media_card(row, "microphone", "Microphone", "ms-settings:privacy-microphone", COLORS["cyan"])

    def _media_card(self, parent, kind, title, _uri, accent):
        card = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(side="left", fill="both", expand=True, padx=(0, 14))
        top = tk.Frame(card, bg=COLORS["panel"]); top.pack(fill="x", padx=18, pady=(17, 8))
        tk.Label(top, text="◉", fg=accent, bg=COLORS["panel"], font=("Segoe UI", 19, "bold")).pack(side="left", padx=(0, 9))
        title_frame = tk.Frame(top, bg=COLORS["panel"]); title_frame.pack(side="left")
        tk.Label(title_frame, text=title, fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 14, "bold")).pack(anchor="w")
        try:
            state = self.controller.media_state(kind)
        except MediaGuardError as exc:
            state = {"mode": "unknown", "locked_until": None, "allowed_sites": [], "system_deny": False, "error": str(exc)}
        mode = state.get("mode", "unlocked")
        if mode == "locked":
            label, color = "ĐANG KHÓA", COLORS["red"]
        elif mode == "temporary":
            label, color = "KHÓA TẠM THỜI", COLORS["amber"]
        elif state.get("system_deny"):
            label, color = "SYSTEM DENY", COLORS["red"]
        else:
            label, color = "ĐANG MỞ", COLORS["green"]
        tk.Label(title_frame, text="●  " + label, fg=color, bg=COLORS["panel"], font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(2, 0))
        tk.Frame(card, bg=COLORS["border"], height=1).pack(fill="x", padx=18)
        controls = tk.Frame(card, bg=COLORS["panel"]); controls.pack(fill="x", padx=18, pady=13)
        lock_button = make_button(controls, "KHÓA", lambda k=kind: self.media_lock(k), bg=COLORS["red"], fg="white", small=True)
        lock_button.pack(side="left")
        temporary_button = make_button(controls, "KHÓA TẠM 15 PHÚT", lambda k=kind: self.media_temporary_lock(k), bg=COLORS["panel_alt"], fg=COLORS["amber"], small=True)
        temporary_button.pack(side="left", padx=6)
        unlock_button = make_button(controls, "MỞ KHÓA", lambda k=kind: self.media_unlock(k), bg=COLORS["green"], fg=COLORS["bg"], small=True)
        unlock_button.pack(side="left")
        settings_button = make_button(card, "MỞ WINDOWS PRIVACY SETTINGS", lambda k=kind: self.open_media_settings(k), bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True)
        settings_button.pack(anchor="w", padx=18, pady=(0, 13))
        if kind == "camera":
            self._register_guide_target("media_camera_status", title_frame)
            self._register_guide_target("media_camera_lock", lock_button)
            self._register_guide_target("media_camera_temporary", temporary_button)
            self._register_guide_target("media_camera_unlock", unlock_button)
            self._register_guide_target("media_camera_settings", settings_button)
        site_title = tk.Frame(card, bg=COLORS["panel"]); site_title.pack(fill="x", padx=18, pady=(4, 6))
        tk.Label(site_title, text="WEBSITE ORIGINS ĐƯỢC PHÉP", fg=COLORS["muted"], bg=COLORS["panel"], font=("Segoe UI", 8, "bold")).pack(side="left")
        tk.Label(site_title, text="browser extension", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 8)).pack(side="right")
        site_tree, site_host = self._scrollable_tree(card, ("origin",), height=4)
        site_tree.heading("origin", text="ORIGIN")
        site_tree.column("origin", width=400)
        site_host.pack(fill="x", padx=18)
        self.media_site_trees[kind] = site_tree
        if kind == "camera":
            self._register_guide_target("media_camera_sites", site_tree)
        for site in state.get("allowed_sites", []):
            site_tree.insert("", "end", values=(site,))
        site_actions = tk.Frame(card, bg=COLORS["panel"]); site_actions.pack(fill="x", padx=18, pady=(8, 17))
        make_button(site_actions, "+ THÊM WEBSITE", lambda k=kind: self.add_media_site(k), bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True).pack(side="left")
        make_button(site_actions, "XÓA WEBSITE", lambda k=kind: self.remove_media_site(k), bg=COLORS["panel_alt"], fg=COLORS["red"], small=True).pack(side="right")

    def media_lock(self, kind):
        label = "camera" if kind == "camera" else "microphone"
        def apply():
            if not messagebox.askyesno("Khóa thiết bị", f"Khóa {label} ở mức Windows? Các ứng dụng đang mở có thể cần khởi động lại.", parent=self):
                return
            try:
                self.controller.set_media_mode(kind, "locked", username=self.username)
                self.toast("Media Guard đã cập nhật", f"{label.capitalize()} đã được khóa ở mức policy Windows.", "success")
                self.show_page("media")
            except MediaGuardError as exc:
                messagebox.showerror("Không thể khóa thiết bị", str(exc), parent=self)
        self._protected_action("Khóa thiết bị media", f"Thao tác này sẽ từ chối quyền truy cập {label} ở mức policy Windows.", apply, force_reauth=True)

    def media_temporary_lock(self, kind):
        def apply():
            try:
                self.controller.set_media_mode(kind, "temporary", minutes=15, username=self.username)
                self.toast("Đã khóa tạm thời", f"{kind.capitalize()} sẽ bị khóa trong 15 phút.", "success")
                self.show_page("media")
            except MediaGuardError as exc:
                messagebox.showerror("Không thể khóa tạm thời", str(exc), parent=self)
        self._protected_action("Khóa media tạm thời", "FileSentry sẽ khôi phục policy trước đó sau 15 phút.", apply, force_reauth=True)

    def media_unlock(self, kind):
        def apply():
            if not messagebox.askyesno("Mở khóa thiết bị", "Khôi phục policy camera/microphone trước đó?", parent=self):
                return
            try:
                self.controller.set_media_mode(kind, "unlocked", username=self.username)
                self.toast("Thiết bị đã mở khóa", f"{kind.capitalize()} có thể được ứng dụng yêu cầu lại.", "success")
                self.show_page("media")
            except MediaGuardError as exc:
                messagebox.showerror("Không thể mở khóa", str(exc), parent=self)
        self._protected_action("Mở khóa thiết bị media", "Chỉ mở khóa khi bạn muốn ứng dụng được phép yêu cầu camera/microphone.", apply, force_reauth=True)

    def open_media_settings(self, kind):
        def open_settings():
            try:
                self.controller.media.open_privacy_settings(kind)
            except MediaGuardError as exc:
                messagebox.showerror("Không thể mở Settings", str(exc), parent=self)
        self._protected_action("Mở Windows Privacy Settings", "Kiểm tra chính sách quyền camera/microphone của Windows.", open_settings, force_reauth=True)

    def add_media_site(self, kind):
        def add():
            origin = simpledialog.askstring("Thêm website", "Origin (ví dụ https://example.com):", parent=self)
            if not origin:
                return
            try:
                self.controller.add_media_site(kind, origin, self.username)
                self.toast("Allowlist đã cập nhật", "Website origin đã được thêm vào danh sách được phép.", "success")
                self.show_page("media")
            except ValueError as exc:
                messagebox.showerror("Origin không hợp lệ", str(exc), parent=self)
        self._protected_action("Thêm website được phép", "Origin này sẽ được lưu để browser extension dùng khi enforcement website được cài.", add, force_reauth=True)

    def remove_media_site(self, kind):
        tree = self.media_site_trees.get(kind)
        selected = tree.selection() if tree else []
        if not selected:
            messagebox.showinfo("Chưa chọn", "Hãy chọn website cần xóa.", parent=self); return
        origin = tree.item(selected[0], "values")[0]
        def remove():
            self.controller.remove_media_site(kind, origin, self.username)
            self.show_page("media")
        self._protected_action("Xóa website được phép", f"Xóa origin khỏi allowlist?\n{origin}", remove, force_reauth=True)

    def open_protected_scope(self):
        status = self.controller.status()
        title = "Mở khóa khu vực bảo vệ" if status.get("access_locked") else "Truy cập khu vực bảo vệ"
        description = "Khu vực quản lý đang bị khóa. Nhập mật khẩu để mở khóa tạm thời." if status.get("access_locked") else "Đây là khu vực nhạy cảm: cấu hình include/exclude và các thao tác xóa bảo vệ yêu cầu xác thực."
        self._protected_action(title, description, self._enter_scope, force_reauth=True)

    def _enter_scope(self):
        if self.controller.status().get("access_locked"):
            self.controller.unlock_protected_access(self.username)
        self.show_page("scope")

    def _scope(self):
        self._header("Protected surface", "Khu vực bảo vệ", "Quản lý nơi FileSentry được phép giám sát và khu vực loại trừ.")
        status = self.controller.status()
        panel = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        panel.pack(fill="x", padx=38, pady=(0, 16))
        tk.Label(panel, text="ACCESS CONTROL", fg=COLORS["cyan"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=17, pady=(14, 4))
        tk.Label(panel, text="Đã xác thực quyền quản trị cho khu vực này.", fg=COLORS["text"], bg=COLORS["panel_soft"], font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=17)
        tk.Label(panel, text="Khóa khu vực chỉ khóa quyền quản lý trong FileSentry ở MVP; chưa phải filesystem lock cấp Windows.", fg=COLORS["muted"], bg=COLORS["panel_soft"], font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(3, 12))
        toolbar = tk.Frame(self.body, bg=COLORS["bg"]); toolbar.pack(fill="x", padx=38, pady=(0, 12))
        include_button = make_button(toolbar, "+ THÊM KHU VỰC", lambda: self.add_path("include"), bg=COLORS["cyan"], fg=COLORS["bg"])
        include_button.pack(side="left")
        self._register_guide_target("scope_include", include_button)
        exclude_button = make_button(toolbar, "+ THÊM LOẠI TRỪ", lambda: self.add_path("exclude"), bg=COLORS["panel_alt"], fg=COLORS["text"])
        exclude_button.pack(side="left", padx=8)
        self._register_guide_target("scope_exclude", exclude_button)
        storage_button = make_button(toolbar, "+ TẠO KHO LƯU TRỮ", self.create_protected_storage, bg=COLORS["green"], fg=COLORS["bg"])
        storage_button.pack(side="left", padx=8)
        self._register_guide_target("scope_storage", storage_button)
        remove_button = make_button(toolbar, "XÓA BẢO VỆ MỤC CHỌN", self.remove_selected_scope, bg=COLORS["panel_alt"], fg=COLORS["red"])
        remove_button.pack(side="right")
        self._register_guide_target("scope_remove", remove_button)
        self._scope_tree(self.body, "KHU VỰC ĐƯỢC BẢO VỆ", status["settings"]["include_paths"], "include")
        self._scope_tree(self.body, "KHU VỰC LOẠI TRỪ", status["settings"]["exclude_paths"], "exclude")
        storage_state = self.controller.protected_storage_state()
        storage_panel = tk.Frame(self.body, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        storage_panel.pack(fill="x", padx=38, pady=(0, 16))
        tk.Label(storage_panel, text="PROTECTED STORAGE AREA", fg=COLORS["cyan"], bg=COLORS["panel"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=17, pady=(14, 4))
        tk.Label(storage_panel, text="Thư mục này được thêm vào phạm vi giám sát để lưu file riêng. FileSentry không tự di chuyển hoặc xóa dữ liệu; muốn khóa quyền Windows, dùng Folder Lock bên dưới.", fg=COLORS["muted"], bg=COLORS["panel"], wraplength=930, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(0, 11))
        storage_tree, storage_tree_host = self._scrollable_tree(storage_panel, ("name", "path", "status", "created"), height=max(2, min(4, len(storage_state.get("areas", [])) + 1)))
        for column, label, width in (("name", "TÊN KHO", 220), ("path", "ĐƯỜNG DẪN", 500), ("status", "TRẠNG THÁI", 150), ("created", "TẠO LÚC", 180)):
            storage_tree.heading(column, text=label); storage_tree.column(column, width=width)
        storage_tree_host.pack(fill="both", expand=True, padx=17)
        self.protected_storage_tree = storage_tree
        self._register_guide_target("storage_tree", storage_tree)
        for area in storage_state.get("areas", []):
            path = Path(area.get("path", ""))
            storage_tree.insert("", "end", iid=area["id"], values=(area.get("name", ""), area.get("path", ""), "ĐANG GIÁM SÁT" if path.is_dir() else "THIẾU THƯ MỤC", (area.get("created_at") or "")[:19].replace("T", " ")))
        storage_actions = tk.Frame(storage_panel, bg=COLORS["panel"]); storage_actions.pack(fill="x", padx=17, pady=(10, 15))
        open_storage_button = make_button(storage_actions, "MỞ THƯ MỤC", self.open_selected_storage, bg=COLORS["panel_alt"], fg=COLORS["cyan"], small=True)
        open_storage_button.pack(side="left")
        self._register_guide_target("storage_open", open_storage_button)
        remove_storage_button = make_button(storage_actions, "GỠ QUẢN LÝ (GIỮ THƯ MỤC)", self.remove_selected_storage, bg=COLORS["panel_alt"], fg=COLORS["red"], small=True)
        remove_storage_button.pack(side="right")
        self._register_guide_target("storage_remove", remove_storage_button)
        lock_state = self.controller.folder_lock_state()
        lock_panel = tk.Frame(self.body, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1)
        lock_panel.pack(fill="both", expand=True, padx=38, pady=(0, 22))
        tk.Label(lock_panel, text="FOLDER LOCK · WINDOWS ACL", fg=COLORS["cyan"], bg=COLORS["panel"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=17, pady=(14, 4))
        integrity_text = "ACL toàn vẹn" if not lock_state.get("integrity_findings") else "CẢNH BÁO: ACL không khớp bản sao"
        integrity_color = COLORS["green"] if not lock_state.get("integrity_findings") else COLORS["red"]
        tk.Label(lock_panel, text=integrity_text, fg=integrity_color, bg=COLORS["panel"], font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=17, pady=(0, 8))
        tk.Label(lock_panel, text="Folder Lock lưu bản sao DACL đã mã hóa trước khi áp Deny ACL. Khi gỡ FileSentry, tất cả mục đang khóa phải được mở khóa và kiểm tra lại trước khi cho phép xóa dữ liệu.", fg=COLORS["muted"], bg=COLORS["panel"], wraplength=930, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=17, pady=(0, 12))
        lock_tree, lock_tree_host = self._scrollable_tree(lock_panel, ("path", "status", "sid", "time"), height=max(2, min(5, len(lock_state.get("locks", [])) + 1)))
        for column, label, width in (("path", "THƯ MỤC", 440), ("status", "TRẠNG THÁI", 130), ("sid", "OWNER SID", 300), ("time", "THỜI GIAN", 170)):
            lock_tree.heading(column, text=label); lock_tree.column(column, width=width)
        lock_tree_host.pack(fill="both", expand=True, padx=17)
        self.folder_lock_tree = lock_tree
        self._register_guide_target("folder_lock_tree", lock_tree)
        for item in lock_state.get("locks", []):
            lock_tree.insert("", "end", iid=item["id"], values=(item.get("original_path", ""), "ĐANG KHÓA" if item.get("status") == "locked" else "ĐÃ MỞ", item.get("owner_sid", ""), (item.get("locked_at") or "")[:19].replace("T", " ")))
        lock_actions = tk.Frame(lock_panel, bg=COLORS["panel"]); lock_actions.pack(fill="x", padx=17, pady=(10, 15))
        lock_button = make_button(lock_actions, "+ KHÓA THƯ MỤC", self.add_folder_lock, bg=COLORS["cyan"], fg=COLORS["bg"], small=True)
        lock_button.pack(side="left")
        self._register_guide_target("folder_lock_add", lock_button)
        unlock_button = make_button(lock_actions, "MỞ KHÓA MỤC CHỌN", self.unlock_selected_folder, bg=COLORS["green"], fg=COLORS["bg"], small=True)
        unlock_button.pack(side="left", padx=8)
        self._register_guide_target("folder_lock_unlock", unlock_button)
        verify_button = make_button(lock_actions, "KIỂM TRA ACL", self.verify_folder_locks, bg=COLORS["panel_alt"], fg=COLORS["amber"], small=True)
        verify_button.pack(side="right")
        self._register_guide_target("folder_lock_verify", verify_button)

    def add_folder_lock(self):
        def choose():
            path = filedialog.askdirectory(title="Chọn thư mục cần khóa ACL")
            if not path:
                return
            try:
                self.controller.lock_folder(path, self.username)
                self.toast("Đã khóa thư mục", "DACL gốc đã được lưu mã hóa trước khi áp khóa Windows.", "success")
                self.show_page("scope")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể khóa thư mục", str(exc), parent=self)
        self._protected_action("Khóa thư mục bằng Windows ACL", "FileSentry sẽ lưu DACL gốc trước, sau đó mới áp quyền từ chối cho tài khoản hiện tại. Không khóa thư mục dữ liệu của FileSentry.", choose, force_reauth=True)

    def unlock_selected_folder(self):
        tree = getattr(self, "folder_lock_tree", None)
        selected = tree.selection() if tree else []
        if not selected:
            messagebox.showinfo("Chưa chọn thư mục", "Hãy chọn một Folder Lock cần mở khóa.", parent=self)
            return
        lock_id = selected[0]
        def unlock():
            if not messagebox.askyesno("Mở khóa thư mục", "Khôi phục chính xác DACL gốc trước khi khóa?", parent=self):
                return
            try:
                self.controller.unlock_folder(lock_id, self.username)
                self.toast("Đã mở khóa thư mục", "DACL gốc đã được khôi phục.", "success")
                self.show_page("scope")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể mở khóa thư mục", str(exc), parent=self)
        self._protected_action("Mở khóa Folder Lock", "Thao tác này khôi phục đúng DACL trước khi khóa, không mở rộng quyền theo cách tùy ý.", unlock, force_reauth=True)

    def verify_folder_locks(self):
        try:
            result = self.controller.verify_folder_lock_integrity(self.username)
            if result.get("ok"):
                self.toast("ACL toàn vẹn", "Không phát hiện thay đổi ngoài FileSentry.", "success")
            else:
                messagebox.showwarning("Cảnh báo ACL", "Phát hiện ACL không khớp bản sao. FileSentry không tự sửa; hãy mở khóa đúng quy trình hoặc kiểm tra quyền Windows.", parent=self)
            self.show_page("scope")
        except (OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror("Không thể kiểm tra ACL", str(exc), parent=self)

    def _scope_tree(self, parent, title, values, kind):
        frame = tk.Frame(parent, bg=COLORS["bg"]); frame.pack(fill="x", padx=38, pady=(0, 15))
        self._section_title(frame, title, f"{len(values)} mục")
        tree, tree_host = self._scrollable_tree(frame, ("path", "kind"), height=max(2, min(5, len(values) + 1)))
        tree.heading("path", text="ĐƯỜNG DẪN"); tree.heading("kind", text="PHẠM VI")
        tree.column("path", width=720); tree.column("kind", width=130)
        tree_host.pack(fill="x")
        for value in values:
            tree.insert("", "end", values=(value, "INCLUDE" if kind == "include" else "EXCLUDE"))
        setattr(self, f"{kind}_tree", tree)
        self._register_guide_target(f"scope_{kind}_tree", tree)
        return tree

    def _quarantine(self):
        self._header("Containment", "Cách ly", "File nghi ngờ được đưa ra khỏi khu vực làm việc và có thể khôi phục.")
        frame = tk.Frame(self.body, bg=COLORS["bg"]); frame.pack(fill="both", expand=True, padx=38, pady=(0, 24))
        self._section_title(frame, "Quarantine inventory", "Khôi phục yêu cầu mật khẩu")
        tree, tree_host = self._scrollable_tree(frame, ("id", "time", "path", "reason", "status"))
        self._register_guide_target("quarantine_tree", tree)
        for column, label, width in (("id", "ID", 110), ("time", "THỜI GIAN", 170), ("path", "FILE GỐC", 420), ("reason", "LÝ DO", 220), ("status", "TRẠNG THÁI", 110)):
            tree.heading(column, text=label); tree.column(column, width=width)
        tree_host.pack(fill="both", expand=True)
        for item in self.controller.quarantine.list_items():
            tree.insert("", "end", iid=item["id"], values=(item["id"][:10], item["quarantined_at"][:19].replace("T", " "), item["original_path"], item["reason"], item["status"]))
        restore_button = make_button(frame, "KHÔI PHỤC MỤC ĐANG CHỌN", lambda: self.restore_quarantine(tree), bg=COLORS["cyan"], fg=COLORS["bg"])
        restore_button.pack(anchor="e", pady=(12, 0))
        self._register_guide_target("quarantine_restore", restore_button)

    def _settings(self):
        self._header("System policy", "Cài đặt hệ thống", "Chính sách hiện tại và trạng thái kiểm soát truy cập.")
        status = self.controller.status(); settings = status["settings"]
        health = self.controller.health_state()
        chain = self.controller.db.verify_intrusion_chain()
        persistence = self.controller.persistence_state()
        folder_locks = self.controller.folder_lock_state()
        theme_mode = self.controller.settings.data.get("theme_mode", self.theme_mode)
        panel = tk.Frame(self.body, bg=COLORS["panel"], highlightbackground=COLORS["border"], highlightthickness=1); panel.pack(fill="x", padx=38, pady=(0, 16))
        rows = [
            ("Tài khoản quản trị", self.username),
            ("Phiên bản ứng dụng", status.get("version", {}).get("app_version", "unknown")),
            ("Giao diện", f"{self._theme_label(theme_mode)} · hiệu lực {self._theme_label(self._resolved_theme)}"),
            ("Trạng thái bảo vệ", status["label"]),
            ("Truy cập khu vực", "Đang khóa" if status.get("access_locked") else "Cho phép sau xác thực"),
            ("Ngưỡng cảnh báo", f"{settings.get('ransomware_threshold')} event / {settings.get('ransomware_window_seconds')} giây"),
            ("Network Guard", "Local-only — không upload"),
            ("AV / EDR posture", health.get("status", "unknown")),
            ("Persistence inventory", f"{persistence.get('count', 0)} mục — read-only"),
            ("Integrity hash-chain", "Hợp lệ" if chain.get("valid") else "CẢNH BÁO — cần kiểm tra"),
            ("Folder Lock ACL", "Toàn vẹn" if not folder_locks.get("integrity_findings") else "CẢNH BÁO — cần xử lý"),
        ]
        for label, value in rows:
            row = tk.Frame(panel, bg=COLORS["panel"]); row.pack(fill="x", padx=18, pady=11)
            tk.Label(row, text=label, fg=COLORS["muted"], bg=COLORS["panel"], width=26, anchor="w", font=("Segoe UI", 9)).pack(side="left")
            tk.Label(row, text=value, fg=COLORS["text"], bg=COLORS["panel"], anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")
        password_button = make_button(panel, "ĐỔI MẬT KHẨU QUẢN TRỊ", self.change_password, bg=COLORS["panel_alt"], fg=COLORS["text"], small=True)
        password_button.pack(anchor="w", padx=18, pady=(1, 18))
        self._register_guide_target("settings_password", password_button)
        emergency_button = make_button(panel, "MỞ KHÓA KHẨN CẤP TẤT CẢ FOLDER LOCK", self.emergency_unlock_all_folders, bg=COLORS["panel_alt"], fg=COLORS["amber"], small=True)
        emergency_button.pack(anchor="w", padx=18, pady=(0, 10))
        self._register_guide_target("settings_emergency", emergency_button)
        uninstall_button = make_button(panel, "GỠ FILESENTRY", self.uninstall_app, bg=COLORS["panel_alt"], fg=COLORS["red"], small=True)
        uninstall_button.pack(anchor="w", padx=18, pady=(0, 18))
        self._register_guide_target("settings_uninstall", uninstall_button)
        note = tk.Frame(self.body, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1); note.pack(fill="x", padx=38)
        tk.Label(note, text="SECURITY NOTE", fg=COLORS["amber"], bg=COLORS["panel_soft"], font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=16, pady=(13, 4))
        tk.Label(note, text="Tắt hoặc tạm dừng chỉ ảnh hưởng đến giám sát của FileSentry. MVP chưa thể chặn truy cập file từ Explorer ở cấp kernel.", fg=COLORS["muted"], bg=COLORS["panel_soft"], wraplength=760, justify="left", font=("Segoe UI", 8)).pack(anchor="w", padx=16, pady=(0, 14))

    def uninstall_app(self):
        def confirm_and_schedule():
            if not messagebox.askyesno(
                "Xác nhận gỡ FileSentry",
                "FileSentry sẽ đóng và gỡ bản EXE hiện tại. Bạn có muốn xóa cả cấu hình, log, quarantine và khóa mã hóa không?",
                parent=self,
            ):
                return
            delete_data = messagebox.askyesno(
                "Xóa toàn bộ dữ liệu",
                "XÓA DỮ LIỆU sẽ mất vĩnh viễn cấu hình, audit, log và toàn bộ file quarantine. Tiếp tục?",
                icon="warning",
                parent=self,
            )
            try:
                self.controller.prepare_uninstall(self.username)
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror(
                    "Không thể tiếp tục gỡ",
                    "FileSentry chưa thể gỡ vì còn Folder Lock chưa được mở khóa và xác minh an toàn.\n\n" + str(exc),
                    parent=self,
                )
                return
            confirmation = simpledialog.askstring(
                "Xác nhận cuối",
                "Nhập chính xác GỠ FILESENTRY để tiếp tục:",
                parent=self,
            )
            if confirmation != "GỠ FILESENTRY":
                messagebox.showinfo("Đã hủy", "Không có dữ liệu nào bị xóa.", parent=self)
                return
            try:
                UninstallManager().schedule(delete_data=delete_data)
            except UninstallError as exc:
                messagebox.showerror("Không thể gỡ", str(exc), parent=self)
                return
            self.controller.stop()
            messagebox.showinfo("Đang gỡ FileSentry", "FileSentry sẽ đóng và tự dọn dẹp sau vài giây.", parent=self)
            self.winfo_toplevel().after(250, self.winfo_toplevel().destroy)

        self._protected_action(
            "Gỡ FileSentry",
            "Thao tác này đóng ứng dụng và có thể xóa vĩnh viễn dữ liệu cục bộ. Bạn sẽ phải xác nhận thêm một lần nữa.",
            confirm_and_schedule,
            force_reauth=True,
        )

    def emergency_unlock_all_folders(self):
        if not messagebox.askyesno(
            "Mở khóa khẩn cấp",
            "Thao tác này dùng quyền Administrator của Windows để khôi phục DACL gốc cho tất cả Folder Lock, không cần mật khẩu FileSentry. Chỉ dùng khi bạn quên mật khẩu chủ. Tiếp tục?",
            icon="warning",
            parent=self,
        ):
            return
        try:
            result = self.controller.emergency_unlock_all_folders(self.username)
            self.toast("Đã mở khóa khẩn cấp", f"Đã khôi phục {len(result.get('unlocked', []))} thư mục và kiểm tra lại ACL.", "warning")
            self.show_page("settings")
        except (OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror("Không thể mở khóa khẩn cấp", str(exc), parent=self)

    def _protected_action(self, title, description, action, force_reauth=False):
        if not force_reauth and self.controller.auth_session.is_valid(self.username):
            self.controller.db.record_audit("protected_action_session_reused", {"username": self.username, "title": title})
            action()
            return
        PasswordGate(self, self.controller, self.username, title, description, action)

    def toggle_protection(self):
        current = self.controller.settings.data.get("enabled", False)
        action = "tắt" if current else "bật"
        def apply():
            if messagebox.askyesno("Xác nhận thay đổi", f"Bạn có chắc muốn {action} toàn bộ giám sát không?", parent=self):
                self.controller.set_protection(not current, self.username)
                self.toast("Trạng thái bảo vệ đã đổi", f"Đã {action} giám sát theo phạm vi cấu hình.", "success")
                self.show_page(self.current_page)
        self._protected_action("Thay đổi trạng thái bảo vệ", f"Thao tác này sẽ {action} giám sát trong toàn bộ phạm vi đã cấu hình.", apply)

    def pause(self, minutes):
        def apply():
            if messagebox.askyesno("Tạm dừng bảo vệ", f"Tạm dừng giám sát trong {minutes} phút?", parent=self):
                self.controller.pause(minutes, self.username)
                self.toast("Đã tạm dừng bảo vệ", f"Giám sát sẽ tạm dừng trong {minutes} phút.", "warning")
                self.show_page(self.current_page)
        self._protected_action("Tạm dừng giám sát", "Trong thời gian tạm dừng, FileSentry không ghi nhận event mới trong phạm vi bảo vệ.", apply)

    def lock_protected_access(self):
        def apply():
            if messagebox.askyesno("Khóa khu vực quản lý", "Khóa quyền truy cập khu vực bảo vệ trong 15 phút?", parent=self):
                self.controller.lock_protected_access(15, self.username)
                self.toast("Khu vực đã khóa", "Cần xác thực lại khi truy cập vùng cấu hình bảo vệ.", "warning")
                self.show_page(self.current_page)
        self._protected_action("Tạm khóa khu vực bảo vệ", "Khu vực include/exclude sẽ yêu cầu xác thực lại trong thời gian khóa.", apply)

    def add_path(self, kind):
        def choose():
            path = filedialog.askdirectory(title="Chọn khu vực bảo vệ" if kind == "include" else "Chọn khu vực loại trừ")
            if path:
                self.controller.add_path(kind, path, self.username)
                self.toast("Phạm vi đã cập nhật", "Khu vực mới đã được thêm vào policy giám sát.", "success")
                self.show_page("scope")
        self._protected_action("Thêm khu vực bảo vệ", "Thay đổi phạm vi sẽ ảnh hưởng trực tiếp đến các thư mục FileSentry giám sát.", choose)

    def create_protected_storage(self):
        def choose():
            parent = filedialog.askdirectory(title="Chọn thư mục gốc cho kho lưu trữ bảo vệ")
            if not parent:
                return
            name = simpledialog.askstring(
                "Tên kho lưu trữ",
                "Nhập tên thư mục riêng cần tạo:",
                initialvalue="FileSentry Protected Storage",
                parent=self,
            )
            if not name:
                return
            try:
                area = self.controller.create_protected_storage(parent, name, self.username)
                self.toast("Đã tạo kho lưu trữ bảo vệ", f"Đã tạo {area['name']} và thêm vào phạm vi giám sát. Thư mục chưa bị khóa ACL.", "success")
                self.show_page("scope")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể tạo kho lưu trữ", str(exc), parent=self)
        self._protected_action("Tạo kho lưu trữ bảo vệ", "FileSentry sẽ tạo một thư mục riêng, thêm vào phạm vi bảo vệ và giữ nguyên mọi file đang có trong thư mục gốc.", choose, force_reauth=True)

    def _selected_storage_area(self):
        tree = getattr(self, "protected_storage_tree", None)
        selected = tree.selection() if tree else []
        if not selected:
            messagebox.showinfo("Chưa chọn kho", "Hãy chọn một kho lưu trữ bảo vệ.", parent=self)
            return None
        return next((area for area in self.controller.protected_storage_state().get("areas", []) if area.get("id") == selected[0]), None)

    def open_selected_storage(self):
        area = self._selected_storage_area()
        if not area:
            return
        def open_folder():
            try:
                path = Path(area["path"])
                if not path.is_dir():
                    raise OSError("Thư mục lưu trữ không còn tồn tại.")
                if os.name != "nt":
                    raise OSError("Mở thư mục trực tiếp chỉ hỗ trợ trên Windows.")
                os.startfile(str(path))
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể mở kho lưu trữ", str(exc), parent=self)
        self._protected_action("Mở kho lưu trữ bảo vệ", "Mở trực tiếp thư mục đã xác thực trong Windows Explorer.", open_folder)

    def remove_selected_storage(self):
        area = self._selected_storage_area()
        if not area:
            return
        def remove():
            if not messagebox.askyesno("Gỡ quản lý kho", "Chỉ gỡ kho khỏi danh sách riêng của FileSentry. Thư mục và toàn bộ file bên trong sẽ được giữ nguyên; phạm vi giám sát hiện tại cũng không bị xóa.", parent=self):
                return
            try:
                self.controller.remove_protected_storage(area["id"], self.username)
                self.toast("Đã gỡ quản lý kho", "Thư mục và file thật vẫn được giữ nguyên.", "warning")
                self.show_page("scope")
            except (OSError, ValueError, RuntimeError) as exc:
                messagebox.showerror("Không thể gỡ quản lý kho", str(exc), parent=self)
        self._protected_action("Gỡ quản lý kho lưu trữ", "Thao tác này chỉ xóa nhãn quản lý riêng trong FileSentry, không xóa thư mục hoặc dữ liệu.", remove, force_reauth=True)

    def remove_selected_scope(self):
        def remove():
            for kind in ("include", "exclude"):
                tree = getattr(self, f"{kind}_tree", None)
                if tree and tree.selection():
                    value = tree.item(tree.selection()[0], "values")[0]
                    if messagebox.askyesno("Xóa bảo vệ", f"Xóa khu vực khỏi phạm vi bảo vệ?\n\n{value}", parent=self):
                        self.controller.remove_path(kind, value, self.username)
                        self.toast("Đã xóa khỏi phạm vi", "Khu vực không còn được FileSentry giám sát.", "success")
                        self.show_page("scope")
                    return
            messagebox.showinfo("Chưa chọn", "Hãy chọn khu vực cần xóa bảo vệ.", parent=self)
        self._protected_action("Xóa bảo vệ khu vực", "Khu vực được chọn sẽ không còn được FileSentry giám sát sau khi xóa.", remove)

    def restore_quarantine(self, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Chưa chọn", "Hãy chọn một file trong quarantine.", parent=self); return
        def restore():
            try:
                self.controller.quarantine.restore(selected[0])
                self.controller.db.record_audit("quarantine_restored", {"id": selected[0], "username": self.username})
                messagebox.showinfo("Đã khôi phục", "File đã được đưa về đường dẫn gốc.", parent=self)
                self.show_page("quarantine")
            except (OSError, ValueError) as exc:
                messagebox.showerror("Không thể khôi phục", str(exc), parent=self)
        self._protected_action("Khôi phục file cách ly", "Chỉ khôi phục nếu bạn đã xác nhận file an toàn.", restore, force_reauth=True)

    def change_password(self):
        dialog = tk.Toplevel(self)
        dialog.title("Đổi mật khẩu quản trị")
        dialog.configure(bg=COLORS["panel"])
        dialog.geometry("500x405")
        dialog.resizable(False, False)
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()
        tk.Frame(dialog, bg=COLORS["cyan"], height=4).pack(fill="x")
        header = tk.Frame(dialog, bg=COLORS["panel_alt"])
        header.pack(fill="x")
        tk.Label(header, text="FS", fg=COLORS["bg"], bg=COLORS["cyan"], font=("Segoe UI", 14, "bold"), width=3).pack(side="left", padx=(24, 12), pady=16)
        text = tk.Frame(header, bg=COLORS["panel_alt"])
        text.pack(side="left", anchor="w")
        tk.Label(text, text="Đổi mật khẩu quản trị", fg=COLORS["text"], bg=COLORS["panel_alt"], font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(text, text="Mật khẩu mới sẽ được mã hóa và lưu cục bộ", fg=COLORS["muted"], bg=COLORS["panel_alt"], font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))
        form = tk.Frame(dialog, bg=COLORS["panel"]); form.pack(fill="x", padx=38, pady=(18, 0))
        fields = []
        for label in ("Mật khẩu hiện tại", "Mật khẩu mới", "Nhập lại mật khẩu mới"):
            tk.Label(form, text=label.upper(), fg=COLORS["muted"], bg=COLORS["panel"], anchor="w", font=("Segoe UI", 8, "bold")).pack(fill="x")
            entry = tk.Entry(form, show="•", bg=COLORS["panel_alt"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat")
            entry.pack(fill="x", ipady=7, pady=(3, 9)); fields.append(entry)
        def save():
            if fields[1].get() != fields[2].get():
                messagebox.showerror("Không khớp", "Hai mật khẩu mới chưa giống nhau.", parent=dialog); return
            try:
                self.controller.auth.change_password(self.username, fields[0].get(), fields[1].get())
            except ValueError as exc:
                messagebox.showerror("Không thể đổi mật khẩu", str(exc), parent=dialog); return
            dialog.destroy(); messagebox.showinfo("Thành công", "Mật khẩu đã được cập nhật.", parent=self)
        tk.Label(dialog, text="Mật khẩu nên có ít nhất 12 ký tự và không trùng với mật khẩu cũ.", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 8)).pack(anchor="w", padx=38, pady=(1, 10))
        make_button(dialog, "LƯU MẬT KHẨU", save, bg=COLORS["cyan"], fg=COLORS["bg"]).pack(fill="x", padx=38, pady=(0, 18))
