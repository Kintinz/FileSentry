"""Small authenticated IPC envelope with one-time nonce challenges.

This module is transport-neutral. A Windows Named Pipe implementation must add
an ACL and Windows client-token validation around this protocol.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time


MAX_MESSAGE_BYTES = 256 * 1024


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class IpcAuthenticator:
    def __init__(self, secret: bytes, challenge_ttl: float = 30.0):
        if len(secret) < 32:
            raise ValueError("IPC secret phải có ít nhất 32 bytes.")
        self.secret = bytes(secret)
        self.challenge_ttl = max(5.0, float(challenge_ttl))
        self._challenges: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()

    def issue_challenge(self, client_id: str) -> dict:
        challenge_id = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(32)
        with self._lock:
            self._challenges[challenge_id] = (str(client_id), nonce, time.monotonic() + self.challenge_ttl)
        return {"challenge_id": challenge_id, "nonce": nonce, "expires_in": self.challenge_ttl}

    def authenticate(self, client_id: str, challenge: dict, request: dict, mac: str) -> bool:
        if len(_canonical(request)) > MAX_MESSAGE_BYTES:
            return False
        challenge_id = str(challenge.get("challenge_id", ""))
        with self._lock:
            stored = self._challenges.pop(challenge_id, None)
        if stored is None or stored[2] <= time.monotonic():
            return False
        expected_client, nonce, _expires = stored
        if expected_client != str(client_id):
            return False
        envelope = {"client_id": expected_client, "nonce": nonce, "request": request}
        expected = hmac.new(self.secret, _canonical(envelope), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, str(mac))

    def sign_request(self, client_id: str, challenge: dict, request: dict) -> str:
        if len(_canonical(request)) > MAX_MESSAGE_BYTES:
            raise ValueError("IPC request quá lớn.")
        envelope = {"client_id": str(client_id), "nonce": str(challenge["nonce"]), "request": request}
        return hmac.new(self.secret, _canonical(envelope), hashlib.sha256).hexdigest()
