"""Recoverable quarantine storage."""

from __future__ import annotations

import hashlib
import json
import shutil
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path

from .paths import QUARANTINE_DIR, QUARANTINE_MANIFEST_DIR
from .secure_storage import AppCrypto
from .security import is_within, reject_symlink


class QuarantineManager:
    def __init__(self, crypto: AppCrypto | None = None, root: Path | None = None):
        base = Path(root) if root is not None else QUARANTINE_DIR.parent
        self.quarantine_dir = base / "quarantine"
        self.manifest_dir = self.quarantine_dir / "manifests"
        self.crypto = crypto or AppCrypto(base)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def list_items(self) -> list[dict]:
        items = []
        for path in self.manifest_dir.glob("*.json"):
            try:
                item, encrypted = self.crypto.read_json(path)
                if not encrypted:
                    stored_path = Path(item.get("stored_path", ""))
                    if stored_path.exists() and not item.get("encrypted", False):
                        temporary_path = stored_path.with_suffix(".migrate.tmp")
                        self.crypto.encrypt_file(stored_path, temporary_path, f"quarantine:{item['id']}")
                        temporary_path.replace(stored_path)
                        item["encrypted"] = True
                    self.crypto.write_json(path, item)
                items.append(item)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        return sorted(items, key=lambda item: item.get("quarantined_at", ""), reverse=True)

    def quarantine_file(self, source: str, reason: str) -> dict:
        raw_source = reject_symlink(Path(source).expanduser())
        source_path = raw_source.resolve(strict=True)
        if is_within(source_path, self.quarantine_dir):
            raise ValueError("Không thể cách ly file đã nằm trong quarantine.")
        if not source_path.is_file():
            raise ValueError("Chỉ có thể cách ly file, không phải thư mục.")
        item_id = uuid.uuid4().hex
        stored_path = self.quarantine_dir / f"{item_id}.quarantined"
        digest = self._hash(source_path)
        temporary_path = stored_path.with_suffix(".tmp")
        try:
            self.crypto.encrypt_file(source_path, temporary_path, f"quarantine:{item_id}")
            temporary_path.replace(stored_path)
            source_path.unlink()
        except Exception:
            temporary_path.unlink(missing_ok=True)
            stored_path.unlink(missing_ok=True)
            raise
        manifest = {
            "id": item_id,
            "original_path": str(source_path),
            "stored_path": str(stored_path),
            "sha256": digest,
            "reason": reason,
            "status": "quarantined",
            "encrypted": True,
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
        }
        self.crypto.write_json(self.manifest_dir / f"{item_id}.json", manifest)
        return manifest

    def restore(self, item_id: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{32}", item_id or ""):
            raise ValueError("Mã quarantine không hợp lệ.")
        manifest_path = self.manifest_dir / f"{item_id}.json"
        manifest, _encrypted = self.crypto.read_json(manifest_path)
        stored_path = Path(manifest["stored_path"])
        destination = Path(manifest["original_path"])
        if not is_within(stored_path, self.quarantine_dir):
            raise ValueError("Manifest quarantine trỏ ra ngoài vùng an toàn.")
        reject_symlink(stored_path, "Kho quarantine không được chứa symbolic link.")
        if destination.exists() and destination.is_symlink():
            raise ValueError("Không khôi phục đè lên symbolic link.")
        if not stored_path.exists():
            raise FileNotFoundError("Không tìm thấy file trong quarantine.")
        if destination.exists():
            raise FileExistsError("Đường dẫn gốc đã có file; không tự ghi đè.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = destination.with_name(destination.name + ".filesentry-restore.tmp")
        if manifest.get("encrypted", False):
            self.crypto.decrypt_file(stored_path, temporary_path, f"quarantine:{item_id}")
            if self._hash(temporary_path) != manifest.get("sha256"):
                temporary_path.unlink(missing_ok=True)
                raise ValueError("Hash file sau giải mã không khớp manifest.")
            temporary_path.replace(destination)
        else:
            shutil.move(str(stored_path), str(destination))
        manifest["status"] = "restored"
        self.crypto.write_json(manifest_path, manifest)
        return manifest
