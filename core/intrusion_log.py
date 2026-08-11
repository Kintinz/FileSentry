"""Tamper-evident local hash-chain for FileSentry security records."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from .secure_storage import AppCrypto
from .security import ensure_private_directory, reject_symlink


class ChainIntegrityError(RuntimeError):
    pass


class IntrusionChain:
    """Append-only encrypted payloads linked by SHA-256 hashes.

    The chain detects modification or reordering while the file remains present.
    It cannot prevent an Administrator from deleting the whole file.
    """

    GENESIS = "0" * 64

    def __init__(self, path: Path, crypto: AppCrypto):
        self.path = Path(path)
        ensure_private_directory(self.path.parent)
        self.crypto = crypto
        self.lock = threading.Lock()
        self._last_hash = self.GENESIS
        if self.path.exists():
            reject_symlink(self.path, "Hash-chain không được là symbolic link.")
            result = self.verify()
            if not result["valid"]:
                raise ChainIntegrityError(result["error"] or "Hash-chain không hợp lệ.")
            self._last_hash = result["last_hash"]

    @staticmethod
    def _canonical(sequence: int, previous_hash: str, kind: str, payload: str) -> bytes:
        return json.dumps(
            {"sequence": sequence, "previous_hash": previous_hash, "kind": kind, "payload": payload},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def append(self, kind: str, payload: dict) -> str:
        with self.lock:
            previous_hash = self._last_hash
            sequence = 1
            if self.path.exists():
                try:
                    lines = self.path.read_text(encoding="utf-8").splitlines()
                    if lines:
                        sequence = int(json.loads(lines[-1])["sequence"]) + 1
                except (OSError, IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ChainIntegrityError("Không thể xác định bản ghi cuối của hash-chain.") from exc
            encrypted_kind = self.crypto.encrypt_text(kind, "chain:kind")
            encrypted_payload = self.crypto.encrypt_text(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")), "chain:payload"
            )
            digest = hashlib.sha256(self._canonical(sequence, previous_hash, encrypted_kind, encrypted_payload)).hexdigest()
            record = {
                "sequence": sequence,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "previous_hash": previous_hash,
                "kind": encrypted_kind,
                "payload": encrypted_payload,
                "record_hash": digest,
            }
            reject_symlink(self.path, "Hash-chain không được là symbolic link.")
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            descriptor = os.open(str(self.path), flags, 0o600)
            try:
                with os.fdopen(descriptor, "ab", closefd=True) as handle:
                    handle.write((json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
            self._last_hash = digest
            return digest

    def verify(self) -> dict:
        if not self.path.exists():
            return {"valid": True, "records": 0, "last_hash": self.GENESIS, "error": None}
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            return {"valid": False, "records": 0, "last_hash": self.GENESIS, "error": str(exc)}
        previous_hash = self.GENESIS
        expected_sequence = 1
        for line in lines:
            try:
                record = json.loads(line)
                sequence = int(record["sequence"])
                record_previous = str(record["previous_hash"])
                encrypted_kind = str(record["kind"])
                encrypted_payload = str(record["payload"])
                actual = str(record["record_hash"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                return {"valid": False, "records": expected_sequence - 1, "last_hash": previous_hash, "error": f"Bản ghi lỗi: {exc}"}
            expected = hashlib.sha256(self._canonical(sequence, record_previous, encrypted_kind, encrypted_payload)).hexdigest()
            if sequence != expected_sequence or record_previous != previous_hash or actual != expected:
                return {"valid": False, "records": expected_sequence - 1, "last_hash": previous_hash, "error": "Phát hiện sửa hoặc đứt hash-chain."}
            previous_hash = actual
            expected_sequence += 1
        return {"valid": True, "records": len(lines), "last_hash": previous_hash, "error": None}
