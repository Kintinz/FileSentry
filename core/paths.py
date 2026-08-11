"""Application paths.

The development default keeps data in the repository so the MVP can run without
an installer. Production installers should set FILESENTRY_DATA_DIR to a protected
location such as C:\\ProgramData\\FileSentry.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .security import ensure_private_directory, harden_windows_acl


PROJECT_ROOT = Path(__file__).resolve().parents[1]
_configured_data_dir = os.environ.get("FILESENTRY_DATA_DIR")
if _configured_data_dir:
    DATA_DIR = Path(_configured_data_dir)
elif sys.platform == "win32" and getattr(sys, "frozen", False):
    DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "FileSentry"
else:
    DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = DATA_DIR / "logs"
QUARANTINE_DIR = DATA_DIR / "quarantine"
QUARANTINE_MANIFEST_DIR = QUARANTINE_DIR / "manifests"
VAULT_DIR = DATA_DIR / "vault_store"
VAULT_MANIFEST_DIR = DATA_DIR / "vault_manifests"
SETTINGS_FILE = DATA_DIR / "settings.json"
AUTH_FILE = DATA_DIR / "auth.json"
DB_FILE = DATA_DIR / "filesentry.db"
VERSION_FILE = DATA_DIR / "version.json"


def ensure_layout(data_dir: Path | None = None) -> None:
    root = Path(data_dir) if data_dir is not None else DATA_DIR
    paths = (
        root,
        root / "logs",
        root / "quarantine",
        root / "quarantine" / "manifests",
        root / "vault_store",
        root / "vault_manifests",
    )
    for path in paths:
        ensure_private_directory(path)
    if data_dir is None and sys.platform == "win32" and getattr(sys, "frozen", False):
        harden_windows_acl(root)
