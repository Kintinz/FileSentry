"""Service-owned encrypted data profile and non-destructive migration."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import uuid
from pathlib import Path

from core.intrusion_log import IntrusionChain
from core.secure_storage import AppCrypto
from core.security import ensure_private_directory, reject_symlink

from .windows_acl import harden_service_profile_acl


class ServiceProfileError(RuntimeError):
    pass


class ServiceDataProfile:
    """Machine-scope DPAPI profile owned by the future Windows service.

    The profile is intentionally separate from the current user-scoped V1
    profile. The GUI must access it through IPC after the service split; it
    must never read this directory directly.
    """

    PROFILE_VERSION = 1

    def __init__(self, root: str | Path | None = None, protect: bool = False):
        if root is None:
            root = Path(os.environ.get("FILESENTRY_SERVICE_DATA_DIR", ""))
            if not str(root):
                root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "FileSentry" / "Service"
        self.root = Path(root).expanduser()
        ensure_private_directory(self.root)
        for path in (
            self.root / "logs",
            self.root / "quarantine",
            self.root / "quarantine" / "manifests",
            self.root / "vault_store",
            self.root / "vault_manifests",
        ):
            ensure_private_directory(path)
        self.crypto = AppCrypto(self.root, dpapi_scope="machine")
        self.marker_path = self.root / "service_profile.json"
        if not self.marker_path.exists():
            self.crypto.write_json(
                self.marker_path,
                {"profile_version": self.PROFILE_VERSION, "scope": "machine", "owner": "FileSentryAgent"},
            )
        if protect:
            harden_service_profile_acl(self.root)


class ServiceDataMigrator:
    """Migrate supported V1 data without touching the source directory.

    A backup is created before staging. The destination is published only after
    every supported file has been decrypted, re-encrypted and verified. Any
    error removes the staging directory while leaving both source and backup.
    """

    JSON_FILES = {"auth.json", "settings.json", "version.json"}
    DB_FIELDS = {
        "events": ("timestamp", "event_type", "path", "old_path", "is_dir", "size", "sha256", "source", "details_json"),
        "alerts": ("timestamp", "severity", "title", "message", "path"),
        "audit_log": ("timestamp", "action", "details_json"),
    }

    def __init__(self, source_root: str | Path, destination_root: str | Path, backup_root: str | Path | None = None, protect: bool = True):
        self.source = Path(source_root).expanduser()
        self.destination = Path(destination_root).expanduser()
        self.backup = Path(backup_root).expanduser() if backup_root else self.source.with_name(f"{self.source.name}.backup-{uuid.uuid4().hex[:12]}")
        self.protect = bool(protect)
        if self.source.resolve() == self.destination.resolve():
            raise ServiceProfileError("Source và destination migration phải khác nhau.")

    def migrate(self) -> dict:
        self._validate_source()
        if self.destination.exists():
            raise ServiceProfileError("Destination Service profile đã tồn tại; không ghi đè tự động.")
        if self.backup.exists():
            raise ServiceProfileError("Backup migration đã tồn tại; chọn đường dẫn khác để tránh ghi đè.")
        self.backup.parent.mkdir(parents=True, exist_ok=True)
        staging = self.destination.with_name(f".{self.destination.name}.staging-{uuid.uuid4().hex}")
        try:
            shutil.copytree(self.source, self.backup, symlinks=False)
            old_crypto = AppCrypto(self.source, dpapi_scope="user")
            profile = ServiceDataProfile(staging, protect=False)
            new_crypto = profile.crypto
            handled: set[Path] = {Path("app_key.dpapi")}
            self._migrate_json(old_crypto, new_crypto, staging, handled)
            self._migrate_stores(old_crypto, new_crypto, staging, handled)
            self._migrate_database(old_crypto, new_crypto, staging, handled)
            self._migrate_chain(old_crypto, new_crypto, staging, handled)
            self._reject_unhandled_files(handled)
            if self.protect:
                harden_service_profile_acl(staging)
            staging.rename(self.destination)
            return {"source": str(self.source), "destination": str(self.destination), "backup": str(self.backup), "profile_version": ServiceDataProfile.PROFILE_VERSION}
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def _validate_source(self) -> None:
        if not self.source.is_dir() or self.source.is_symlink():
            raise ServiceProfileError("Source V1 data profile không hợp lệ.")
        for path in self.source.rglob("*"):
            if path.is_symlink():
                raise ServiceProfileError(f"Source chứa symbolic link: {path}")

    def _migrate_json(self, old_crypto: AppCrypto, new_crypto: AppCrypto, staging: Path, handled: set[Path]) -> None:
        for source_path in self.source.rglob("*.json"):
            relative = source_path.relative_to(self.source)
            item, _encrypted = old_crypto.read_json(source_path)
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            new_crypto.write_json(destination, item)
            handled.add(relative)

    def _migrate_stores(self, old_crypto: AppCrypto, new_crypto: AppCrypto, staging: Path, handled: set[Path]) -> None:
        for source_path in self.source.rglob("*"):
            if not source_path.is_file() or source_path.suffix not in {".vault", ".quarantined"}:
                continue
            relative = source_path.relative_to(self.source)
            item_id = source_path.stem
            purpose = "vault" if source_path.suffix == ".vault" else "quarantine"
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = staging / f".migration-{uuid.uuid4().hex}.tmp"
            try:
                old_crypto.decrypt_file(source_path, temporary, f"{purpose}:{item_id}")
                new_crypto.encrypt_file(temporary, destination, f"{purpose}:{item_id}")
            finally:
                temporary.unlink(missing_ok=True)
            handled.add(relative)

    def _migrate_database(self, old_crypto: AppCrypto, new_crypto: AppCrypto, staging: Path, handled: set[Path]) -> None:
        source_path = self.source / "filesentry.db"
        if not source_path.exists():
            return
        reject_symlink(source_path, "Source database không được là symbolic link.")
        source_connection = sqlite3.connect(source_path)
        try:
            source_connection.execute("PRAGMA wal_checkpoint(FULL)")
        finally:
            source_connection.close()
        destination = staging / "filesentry.db"
        shutil.copy2(source_path, destination)
        connection = sqlite3.connect(destination)
        try:
            for table, fields in self.DB_FIELDS.items():
                rows = connection.execute(f"SELECT id, {', '.join(fields)} FROM {table}").fetchall()
                for row in rows:
                    updates = {}
                    for index, field in enumerate(fields, start=1):
                        value = row[index]
                        purpose = f"events:{field}" if table == "events" else f"alerts:{field}" if table == "alerts" else f"audit:{field}"
                        if value is None:
                            continue
                        text = str(value)
                        plaintext = old_crypto.decrypt_text(text, purpose) if old_crypto.is_encrypted(text) else text
                        updates[field] = new_crypto.encrypt_text(plaintext, purpose)
                    if updates:
                        assignments = ", ".join(f"{field}=?" for field in updates)
                        connection.execute(f"UPDATE {table} SET {assignments} WHERE id=?", (*updates.values(), row[0]))
            connection.commit()
        finally:
            connection.close()
        handled.add(Path("filesentry.db"))

    def _migrate_chain(self, old_crypto: AppCrypto, new_crypto: AppCrypto, staging: Path, handled: set[Path]) -> None:
        source_path = self.source / "logs" / "intrusion_chain.log"
        if not source_path.exists():
            return
        reject_symlink(source_path, "Source hash-chain không được là symbolic link.")
        lines = source_path.read_text(encoding="utf-8").splitlines()
        source_previous_hash = IntrusionChain.GENESIS
        previous_hash = IntrusionChain.GENESIS
        destination = staging / "logs" / "intrusion_chain.log"
        destination.parent.mkdir(parents=True, exist_ok=True)
        migrated = []
        for expected_sequence, line in enumerate(lines, start=1):
            record = json.loads(line)
            sequence = int(record["sequence"])
            if sequence != expected_sequence or str(record["previous_hash"]) != source_previous_hash:
                raise ServiceProfileError("Source hash-chain không hợp lệ; migration bị dừng.")
            source_digest = hashlib.sha256(
                IntrusionChain._canonical(sequence, source_previous_hash, str(record["kind"]), str(record["payload"]))
            ).hexdigest()
            if source_digest != str(record["record_hash"]):
                raise ServiceProfileError("Source hash-chain không hợp lệ; migration bị dừng.")
            source_previous_hash = source_digest
            kind = old_crypto.decrypt_text(str(record["kind"]), "chain:kind")
            payload = old_crypto.decrypt_text(str(record["payload"]), "chain:payload")
            encrypted_kind = new_crypto.encrypt_text(kind, "chain:kind")
            encrypted_payload = new_crypto.encrypt_text(payload, "chain:payload")
            digest = hashlib.sha256(IntrusionChain._canonical(sequence, previous_hash, encrypted_kind, encrypted_payload)).hexdigest()
            migrated_record = {
                "sequence": sequence,
                "timestamp": record["timestamp"],
                "previous_hash": previous_hash,
                "kind": encrypted_kind,
                "payload": encrypted_payload,
                "record_hash": digest,
            }
            migrated.append(migrated_record)
            previous_hash = digest
        destination.write_text("".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in migrated), encoding="utf-8")
        handled.add(Path("logs") / "intrusion_chain.log")

    def _reject_unhandled_files(self, handled: set[Path]) -> None:
        ignored = {Path("app_key.dpapi")}
        for source_path in self.source.rglob("*"):
            if not source_path.is_file():
                continue
            relative = source_path.relative_to(self.source)
            if relative in handled or relative in ignored or relative.name in {"filesentry.db-shm", "filesentry.db-wal"}:
                continue
            raise ServiceProfileError(f"Source có file chưa được migration an toàn: {relative}")
