"""File-level encrypted vault. It is storage, not a real-time folder lock."""

from __future__ import annotations

import hashlib
import json
import re
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .paths import VAULT_DIR, VAULT_MANIFEST_DIR
from .secure_storage import AppCrypto
from .security import is_within, reject_symlink


class VaultManager:
    FORMAT_VERSION = 1

    def __init__(self, crypto: AppCrypto | None = None, root: Path | None = None, access_gateway=None):
        self.vault_dir = Path(root) / "vault_store" if root else VAULT_DIR
        self.manifest_dir = Path(root) / "vault_manifests" if root else VAULT_MANIFEST_DIR
        self.crypto = crypto or AppCrypto(self.vault_dir.parent)
        self.access_gateway = access_gateway
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)

    def _require_access(self) -> None:
        if self.access_gateway is not None:
            self.access_gateway.require_unlock_token("vault")

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _valid_id(item_id: str) -> bool:
        return bool(re.fullmatch(r"[0-9a-f]{32}", item_id or ""))

    def list_items(self) -> list[dict]:
        items = []
        for path in self.manifest_dir.glob("*.json"):
            try:
                item, encrypted = self.crypto.read_json(path)
                if not encrypted:
                    self.crypto.write_json(path, item)
                items.append(item)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        return sorted(items, key=lambda item: item.get("created_at", ""), reverse=True)

    def import_file(self, source: str, remove_source: bool = False, export_blocked: bool = False) -> dict:
        self._require_access()
        raw_source = reject_symlink(Path(source).expanduser())
        source_path = raw_source.resolve(strict=True)
        if is_within(source_path, self.vault_dir):
            raise ValueError("Không thể đưa file vault vào chính vault.")
        if not source_path.is_file():
            raise ValueError("Vault chỉ nhận file, không nhận thư mục.")
        item_id = uuid.uuid4().hex
        stored_path = self.vault_dir / f"{item_id}.vault"
        temporary_path = stored_path.with_suffix(".tmp")
        digest = self._hash(source_path)
        try:
            self.crypto.encrypt_file(source_path, temporary_path, f"vault:{item_id}")
            temporary_path.replace(stored_path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            stored_path.unlink(missing_ok=True)
            raise
        manifest = {
            "id": item_id,
            "original_path": str(source_path),
            "stored_path": str(stored_path),
            "sha256": digest,
            "size": source_path.stat().st_size,
            "status": "stored",
            "export_blocked": bool(export_blocked),
            "format_version": self.FORMAT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.crypto.write_json(self.manifest_dir / f"{item_id}.json", manifest)
        if remove_source:
            try:
                source_path.unlink()
            except OSError:
                stored_path.unlink(missing_ok=True)
                (self.manifest_dir / f"{item_id}.json").unlink(missing_ok=True)
                raise
        return manifest

    def restore(self, item_id: str, destination: str) -> dict:
        self._require_access()
        if not self._valid_id(item_id):
            raise ValueError("Mã vault không hợp lệ.")
        manifest, _encrypted = self.crypto.read_json(self.manifest_dir / f"{item_id}.json")
        if manifest.get("export_blocked"):
            raise PermissionError("Mục này đang ở chế độ không xuất; không thể tạo lại file thường bên ngoài FileSentry.")
        stored_path = Path(manifest["stored_path"])
        if not is_within(stored_path, self.vault_dir):
            raise ValueError("Manifest vault trỏ ra ngoài vùng an toàn.")
        reject_symlink(stored_path, "Kho vault không được chứa symbolic link.")
        destination_path = Path(destination).expanduser()
        if destination_path.exists():
            raise FileExistsError("Đường dẫn khôi phục đã tồn tại; không tự ghi đè.")
        if destination_path.is_symlink():
            raise ValueError("Không khôi phục qua symbolic link.")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = destination_path.with_name(destination_path.name + ".filesentry-vault.tmp")
        try:
            self.crypto.decrypt_file(stored_path, temporary_path, f"vault:{item_id}")
            if self._hash(temporary_path) != manifest.get("sha256"):
                raise ValueError("Hash file sau giải mã không khớp manifest.")
            temporary_path.replace(destination_path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
        manifest["last_restored_path"] = str(destination_path)
        manifest["status"] = "restored"
        self.crypto.write_json(self.manifest_dir / f"{item_id}.json", manifest)
        return manifest

    def read_bytes(self, item_id: str, max_bytes: int = 32 * 1024 * 1024) -> bytes:
        """Read a bounded Vault item into memory for an in-app image preview.

        This never creates an external file and is intentionally limited to
        small previews; video/audio playback remains external-file only.
        """
        self._require_access()
        if not self._valid_id(item_id):
            raise ValueError("Mã vault không hợp lệ.")
        manifest, _encrypted = self.crypto.read_json(self.manifest_dir / f"{item_id}.json")
        stored_path = Path(manifest["stored_path"])
        if not is_within(stored_path, self.vault_dir):
            raise ValueError("Manifest vault trỏ ra ngoài vùng an toàn.")
        reject_symlink(stored_path, "Kho vault không được chứa symbolic link.")
        output = bytearray()
        with stored_path.open("rb") as input_file:
            if input_file.read(4) != b"FSQ1":
                raise ValueError("Kho vault không có định dạng mã hóa hợp lệ.")
            index = 0
            while True:
                size_bytes = input_file.read(4)
                if not size_bytes:
                    break
                if len(size_bytes) != 4:
                    raise ValueError("File vault bị thiếu dữ liệu.")
                size = struct.unpack(">I", size_bytes)[0]
                if size < 16 or size > 1024 * 1024 + 16:
                    raise ValueError("Kích thước chunk vault không hợp lệ.")
                nonce = input_file.read(12)
                ciphertext = input_file.read(size)
                if len(nonce) != 12 or len(ciphertext) != size:
                    raise ValueError("File vault bị thiếu chunk.")
                chunk = self.crypto.aead.decrypt(nonce, ciphertext, f"vault:{item_id}:{index}".encode("utf-8"))
                if len(output) + len(chunk) > max_bytes:
                    raise ValueError("File quá lớn để xem trước an toàn trong bộ nhớ.")
                output.extend(chunk)
                index += 1
        return bytes(output)
