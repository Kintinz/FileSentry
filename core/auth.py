"""Local authentication with a temporary seeded administrator account."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
from pathlib import Path

from .secure_storage import AppCrypto


DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "FileSentry@2026!"
PBKDF2_ITERATIONS = 600_000
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 30.0


class AuthError(ValueError):
    pass


class AuthManager:
    def __init__(self, path: Path, crypto: AppCrypto | None = None):
        self.path = path
        self.crypto = crypto or AppCrypto(path.parent)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._failure_count = 0
        self._locked_until = 0.0
        self._auth_lock = threading.Lock()
        self.ensure_seeded()

    @staticmethod
    def _derive(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=32
        )

    @classmethod
    def _record(cls, password: str, must_change: bool) -> dict:
        salt = os.urandom(16)
        digest = cls._derive(password, salt, PBKDF2_ITERATIONS)
        return {
            "username": DEFAULT_USERNAME,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "password_hash": base64.b64encode(digest).decode("ascii"),
            "must_change_password": must_change,
        }

    def ensure_seeded(self) -> None:
        if not self.path.exists():
            self._write(self._record(DEFAULT_PASSWORD, True))
            return
        # Migrate the pre-encryption MVP file on first startup.
        record, encrypted = self.crypto.read_json(self.path)
        if not encrypted:
            self._write(record)

    def _read(self) -> dict:
        record, encrypted = self.crypto.read_json(self.path)
        if not encrypted:
            self._write(record)
        return record

    def _write(self, record: dict) -> None:
        self.crypto.write_json(self.path, record)

    def authenticate(self, username: str, password: str) -> tuple[bool, bool]:
        with self._auth_lock:
            now = time.monotonic()
            record = self._read()
            persisted_lock_until = float(record.get("locked_until_epoch", 0.0) or 0.0)
            if now < self._locked_until or time.time() < persisted_lock_until:
                return False, False
            if self._locked_until or persisted_lock_until:
                self._locked_until = 0.0
                self._failure_count = 0
                record["failed_attempts"] = 0
                record["locked_until_epoch"] = 0.0
                self._write(record)

            stored_username = str(record.get("username", ""))
            salt = base64.b64decode(record["salt"])
            candidate = self._derive(password, salt, int(record["iterations"]))
            password_valid = hmac.compare_digest(
                base64.b64encode(candidate).decode("ascii"), record["password_hash"]
            )
            username_valid = hmac.compare_digest(str(username), stored_username)
            valid = username_valid and password_valid
            if valid:
                self._failure_count = 0
                if record.get("failed_attempts") or record.get("locked_until_epoch"):
                    record["failed_attempts"] = 0
                    record["locked_until_epoch"] = 0.0
                    self._write(record)
                return True, bool(record.get("must_change_password", False))

            self._failure_count += 1
            persisted_failures = int(record.get("failed_attempts", 0) or 0) + 1
            if self._failure_count >= MAX_FAILED_ATTEMPTS or persisted_failures >= MAX_FAILED_ATTEMPTS:
                self._failure_count = 0
                self._locked_until = now + LOCKOUT_SECONDS
                record["failed_attempts"] = 0
                record["locked_until_epoch"] = time.time() + LOCKOUT_SECONDS
            else:
                record["failed_attempts"] = persisted_failures
                record["locked_until_epoch"] = 0.0
            self._write(record)
            return False, False

    def change_password(self, username: str, current_password: str, new_password: str) -> None:
        self.validate_password(new_password)
        valid, _ = self.authenticate(username, current_password)
        if not valid:
            raise AuthError("Mật khẩu hiện tại không đúng.")
        record = self._record(new_password, False)
        record["username"] = username
        self._write(record)

    def public_parameters(self, username: str) -> dict:
        """Return only password-proof parameters, never the password verifier."""

        with self._auth_lock:
            record = self._read()
            if not hmac.compare_digest(str(username), str(record.get("username", ""))):
                raise AuthError("Tài khoản không hợp lệ.")
            return {
                "username": str(record["username"]),
                "algorithm": str(record.get("algorithm", "PBKDF2-HMAC-SHA256")),
                "iterations": int(record["iterations"]),
                "salt": str(record["salt"]),
            }

    def verify_password_proof(self, username: str, message: bytes, proof: str) -> tuple[bool, bool]:
        """Verify a challenge proof without receiving the plaintext password."""

        with self._auth_lock:
            now = time.monotonic()
            record = self._read()
            persisted_lock_until = float(record.get("locked_until_epoch", 0.0) or 0.0)
            if now < self._locked_until or time.time() < persisted_lock_until:
                return False, False
            if not hmac.compare_digest(str(username), str(record.get("username", ""))):
                return False, False
            verifier = base64.b64decode(str(record["password_hash"]))
            expected = hmac.new(verifier, message, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected, str(proof)):
                self._failure_count = 0
                record["failed_attempts"] = 0
                record["locked_until_epoch"] = 0.0
                self._write(record)
                return True, bool(record.get("must_change_password", False))

            self._failure_count += 1
            failures = int(record.get("failed_attempts", 0) or 0) + 1
            if self._failure_count >= MAX_FAILED_ATTEMPTS or failures >= MAX_FAILED_ATTEMPTS:
                self._failure_count = 0
                self._locked_until = now + LOCKOUT_SECONDS
                record["failed_attempts"] = 0
                record["locked_until_epoch"] = time.time() + LOCKOUT_SECONDS
            else:
                record["failed_attempts"] = failures
                record["locked_until_epoch"] = 0.0
            self._write(record)
            return False, False

    @staticmethod
    def validate_password(password: str) -> None:
        """Require a password that is usable for a local administrator account."""

        if len(password) < 12:
            raise AuthError("Mật khẩu mới phải có ít nhất 12 ký tự.")
        if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
            raise AuthError("Mật khẩu phải có chữ hoa và chữ thường.")
        if not re.search(r"\d", password) or not re.search(r"[^A-Za-z0-9]", password):
            raise AuthError("Mật khẩu phải có số và ký tự đặc biệt.")
