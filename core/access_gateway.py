"""In-memory unlock sessions for sensitive FileSentry resources."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass


@dataclass
class _Grant:
    resource: str
    token_digest: str
    issued_at_mono: float
    expires_at_mono: float
    expires_at_epoch: float


class AccessGateway:
    """Keep short-lived unlock grants out of persistent storage.

    The gateway is an application session gate, not an OS security boundary.
    Windows policy changes are still performed by the resource-specific adapter.
    """

    DEFAULT_MINUTES = 30
    MAX_MINUTES = 24 * 60

    def __init__(self, default_minutes: int = DEFAULT_MINUTES):
        self.default_minutes = max(1, min(int(default_minutes), self.MAX_MINUTES))
        self._grants: dict[str, _Grant] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def unlock(self, resource: str, minutes: int | None = None) -> str:
        resource = str(resource).strip()
        if not resource or len(resource) > 128:
            raise ValueError("Tài nguyên cần mở khóa không hợp lệ.")
        duration = self.default_minutes if minutes is None else max(1, min(int(minutes), self.MAX_MINUTES))
        now_mono = time.monotonic()
        now_epoch = time.time()
        token = secrets.token_urlsafe(32)
        grant = _Grant(
            resource,
            self._digest(token),
            now_mono,
            now_mono + duration * 60,
            now_epoch + duration * 60,
        )
        with self._lock:
            self._grants[resource] = grant
        return token

    def lock(self, resource: str) -> None:
        with self._lock:
            self._grants.pop(str(resource), None)

    def _get_valid(self, resource: str) -> _Grant | None:
        grant = self._grants.get(str(resource))
        if grant is None:
            return None
        if grant.expires_at_mono <= time.monotonic():
            self._grants.pop(str(resource), None)
            return None
        return grant

    def is_unlocked(self, resource: str, token: str | None = None) -> bool:
        with self._lock:
            grant = self._get_valid(resource)
            if grant is None:
                return False
            if token is not None and not secrets.compare_digest(grant.token_digest, self._digest(token)):
                return False
            return True

    def require_unlock_token(self, resource: str, token: str | None = None) -> None:
        if not self.is_unlocked(resource, token):
            raise PermissionError(f"Tài nguyên chưa được mở khóa qua FileSentry: {resource}")

    def status(self, resource: str) -> dict:
        with self._lock:
            grant = self._get_valid(resource)
            if grant is None:
                return {"resource": str(resource), "unlocked": False, "expires_at": None, "remaining_seconds": 0}
            remaining = max(0, int(grant.expires_at_mono - time.monotonic()))
            return {
                "resource": grant.resource,
                "unlocked": True,
                "expires_at": grant.expires_at_epoch,
                "remaining_seconds": remaining,
            }

    def snapshot(self) -> list[dict]:
        with self._lock:
            resources = list(self._grants)
        return [self.status(resource) for resource in resources]
