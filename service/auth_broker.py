"""Password-proof and capability sessions owned by the V2 Service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass


@dataclass
class _Challenge:
    challenge_id: str
    client_id: str
    username: str
    nonce: str
    expires_at: float


@dataclass
class _Session:
    client_id: str
    username: str
    token_digest: str
    issued_at: float
    expires_at: float


@dataclass
class _Capability:
    client_id: str
    resource: str
    token_digest: str
    expires_at: float


class ServiceAuthBroker:
    """Keep authentication challenges and capabilities in Service memory only."""

    DEFAULT_TTL_SECONDS = 15 * 60
    CHALLENGE_TTL_SECONDS = 30

    def __init__(self, auth_manager, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.auth = auth_manager
        self.ttl_seconds = max(60, int(ttl_seconds))
        self._challenges: dict[str, _Challenge] = {}
        self._sessions: dict[str, _Session] = {}
        self._capabilities: dict[str, _Capability] = {}
        self._lock = threading.RLock()

    def begin(self, client_id: str, username: str) -> dict:
        parameters = self.auth.public_parameters(username)
        challenge_id = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(32)
        with self._lock:
            self._challenges[challenge_id] = _Challenge(
                challenge_id, str(client_id), str(username), nonce, time.monotonic() + self.CHALLENGE_TTL_SECONDS
            )
        return {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "expires_in": self.CHALLENGE_TTL_SECONDS,
            **parameters,
        }

    def verify(self, client_id: str, challenge_id: str, proof: str) -> dict:
        with self._lock:
            challenge = self._challenges.pop(str(challenge_id), None)
        if challenge is None or challenge.expires_at <= time.monotonic() or challenge.client_id != str(client_id):
            raise PermissionError("Password proof challenge không hợp lệ hoặc đã hết hạn.")
        message = self._proof_message(client_id, challenge)
        valid, must_change = self.auth.verify_password_proof(challenge.username, message, proof)
        if not valid:
            raise PermissionError("Password proof không hợp lệ.")
        token = secrets.token_urlsafe(32)
        now = time.monotonic()
        session = _Session(str(client_id), challenge.username, self._digest(token), now, now + self.ttl_seconds)
        with self._lock:
            self._sessions[session.token_digest] = session
        return {"session_token": token, "expires_in": self.ttl_seconds, "must_change_password": must_change}

    def require_session(self, client_id: str, token: str, username: str | None = None) -> bool:
        digest = self._digest(token)
        with self._lock:
            session = self._sessions.get(digest)
            if session is None or session.expires_at <= time.monotonic():
                self._sessions.pop(digest, None)
                return False
            if session.client_id != str(client_id):
                return False
            return username is None or session.username == str(username)

    def issue_capability(self, client_id: str, session_token: str, resource: str, ttl_seconds: int = 300) -> str:
        if not self.require_session(client_id, session_token):
            raise PermissionError("Service session chưa được xác thực.")
        # Capabilities are separate short-lived opaque grants. The resource is
        # bound into the digest so a token for one resource cannot authorize another.
        duration = max(1, min(int(ttl_seconds), self.ttl_seconds))
        capability = secrets.token_urlsafe(32)
        digest = self._digest(capability)
        with self._lock:
            self._capabilities[digest] = _Capability(
                str(client_id), str(resource), digest, time.monotonic() + duration
            )
        return capability

    def require_capability(self, client_id: str, capability: str, resource: str) -> bool:
        digest = self._digest(capability)
        with self._lock:
            grant = self._capabilities.get(digest)
            if grant is None or grant.expires_at <= time.monotonic():
                self._capabilities.pop(digest, None)
                return False
            return grant.client_id == str(client_id) and grant.resource == str(resource)

    @staticmethod
    def derive_proof(password: str, challenge: dict, client_id: str) -> str:
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.b64decode(str(challenge["salt"])),
            int(challenge["iterations"]),
            dklen=32,
        )
        message = ServiceAuthBroker.proof_message_from_values(
            client_id, challenge["challenge_id"], challenge["username"], challenge["nonce"]
        )
        return hmac.new(candidate, message, hashlib.sha256).hexdigest()

    @staticmethod
    def proof_message_from_values(client_id: str, challenge_id: str, username: str, nonce: str) -> bytes:
        return f"filesentry-service-auth-v1|{client_id}|{challenge_id}|{username}|{nonce}".encode("utf-8")

    @classmethod
    def _proof_message(cls, client_id: str, challenge: _Challenge) -> bytes:
        return cls.proof_message_from_values(client_id, challenge.challenge_id, challenge.username, challenge.nonce)

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()
