"""Product identity shared by the desktop shell and packaging."""

from pathlib import Path
import ctypes
import os
import sys


PRODUCT_NAME = "FileSentry Sentinel"
PRODUCT_SHORT_NAME = "Sentinel"
PRODUCT_EXE_NAME = "FileSentrySentinel.exe"
PRODUCT_SLUG = "FileSentrySentinel"
ICON_PATH = Path(__file__).resolve().parents[1] / "assets" / "filesentry-sentinel.ico"


def runtime_icon_path() -> Path:
    """Return the icon path available both from source and one-file EXE."""
    if getattr(sys, "frozen", False):
        bundled = Path(getattr(sys, "_MEIPASS", "")) / "assets" / ICON_PATH.name
        if bundled.is_file():
            return bundled
        executable = Path(sys.executable)
        if executable.is_file():
            return executable
    return ICON_PATH


def apply_window_identity(window) -> None:
    """Apply the product identity used by Windows taskbar and Tk windows."""
    if os.name == "nt":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "FileSentry.Sentinel"
            )
        except (AttributeError, OSError):
            pass
    icon = runtime_icon_path()
    if icon.is_file():
        try:
            # Set the icon for the current window and Tk's default for every
            # Toplevel created later (auth dialogs, guides and previews).
            window.iconbitmap(str(icon))
            window.iconbitmap(default=str(icon))
        except Exception:
            pass
