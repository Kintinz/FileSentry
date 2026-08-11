"""FileSentry desktop entry point."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from core.controller import FileSentryController
from core.branding import PRODUCT_EXE_NAME, PRODUCT_NAME, apply_window_identity
from core.elevation import is_admin
from gui.app import LoginView, install_window_chrome


def main() -> None:
    if not is_admin():
        root = tk.Tk()
        apply_window_identity(root)
        root.withdraw()
        messagebox.showerror(
            f"{PRODUCT_NAME} cần quyền Administrator",
            f"Hãy chạy {PRODUCT_EXE_NAME} đã build với manifest requireAdministrator. "
            f"{PRODUCT_NAME} không tự bypass UAC.",
        )
        root.destroy()
        return
    controller = FileSentryController()
    root = tk.Tk()
    apply_window_identity(root)
    root.title(PRODUCT_NAME)
    root.minsize(480, 360)
    install_window_chrome(root, PRODUCT_NAME)
    LoginView(root, controller).pack(fill="both", expand=True)
    root.mainloop()


if __name__ == "__main__":
    main()
