"""Application, database and vault format version metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .security import reject_symlink


APP_VERSION = "0.2.0"
DB_SCHEMA_VERSION = 1
VAULT_FORMAT_VERSION = 1


class VersionStore:
    def __init__(self, path: Path, crypto):
        self.path = Path(path)
        self.crypto = crypto
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict:
        current = {
            "app_version": APP_VERSION,
            "db_schema_version": DB_SCHEMA_VERSION,
            "vault_format_version": VAULT_FORMAT_VERSION,
        }
        saved = {}
        encrypted = False
        if self.path.exists():
            reject_symlink(self.path, "Metadata version không được là symbolic link.")
            saved, encrypted = self.crypto.read_json(self.path)
            if isinstance(saved, dict):
                current.update({key: saved[key] for key in current if key in saved})
        current["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._data = current
        if not encrypted or saved != current:
            self.crypto.write_json(self.path, current)
        return dict(current)

    @property
    def data(self) -> dict:
        return dict(self._data)

