"""Short-lived in-memory authentication session for the desktop UI."""

from __future__ import annotations

import threading
import time


class AuthSession:
    """Remember successful authentication without retaining the password."""

    TTL_SECONDS = 15 * 60

    def __init__(self, ttl_seconds: int = TTL_SECONDS):
        self.ttl_seconds = max(60, int(ttl_seconds))
        self._username: str | None = None
        self._expires_at = 0.0
        self._lock = threading.RLock()

    def open(self, username: str) -> None:
        with self._lock:
            self._username = str(username)
            self._expires_at = time.monotonic() + self.ttl_seconds

    def clear(self) -> None:
        with self._lock:
            self._username = None
            self._expires_at = 0.0

    def is_valid(self, username: str) -> bool:
        with self._lock:
            if self._username != str(username) or self._expires_at <= time.monotonic():
                if self._expires_at <= time.monotonic():
                    self._username = None
                    self._expires_at = 0.0
                return False
            return True

    def status(self, username: str | None = None) -> dict:
        with self._lock:
            valid = bool(self._username and self._expires_at > time.monotonic())
            if username is not None:
                valid = valid and self._username == str(username)
            remaining = max(0, int(self._expires_at - time.monotonic())) if valid else 0
            if not valid and self._expires_at <= time.monotonic():
                self._username = None
                self._expires_at = 0.0
            return {"authenticated": valid, "remaining_seconds": remaining}
