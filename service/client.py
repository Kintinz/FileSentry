"""Thin-client helper for the authenticated FileSentry Agent pipe."""

from __future__ import annotations

from .auth_broker import ServiceAuthBroker
from .named_pipe import NamedPipeClient, NamedPipeConfig


class ServiceClientError(RuntimeError):
    pass


class ServiceClient:
    """Small UI/tray-side client; it never stores a plaintext password."""

    def __init__(self, shared_secret: bytes, client_id: str = "ui", config: NamedPipeConfig | None = None):
        self.client_id = str(client_id)
        self.pipe = NamedPipeClient(shared_secret, self.client_id, config)
        self.username: str | None = None
        self.session_token: str | None = None

    def call(self, request: dict) -> dict:
        response = self.pipe.request(dict(request))
        if not response.get("ok"):
            raise ServiceClientError(str(response.get("error", "Service request failed.")))
        result = response.get("result", {})
        if not isinstance(result, dict):
            raise ServiceClientError("Service response không hợp lệ.")
        return result

    def authenticate(self, username: str, password: str) -> dict:
        challenge = self.call({"action": "auth_begin", "username": str(username)})
        proof = ServiceAuthBroker.derive_proof(password, challenge, self.client_id)
        session = self.call({
            "action": "auth_proof",
            "challenge_id": challenge["challenge_id"],
            "proof": proof,
        })
        token = str(session.get("session_token", ""))
        if not token:
            raise ServiceClientError("Service không cấp session token.")
        self.username = str(username)
        self.session_token = token
        return session

    def status(self) -> dict:
        return self.call({"action": "status"})

    def issue_capability(self, resource: str, ttl_seconds: int = 300) -> str:
        if not self.session_token:
            raise ServiceClientError("Chưa xác thực Service session.")
        result = self.call({
            "action": "issue_capability",
            "session_token": self.session_token,
            "resource": str(resource),
            "ttl_seconds": int(ttl_seconds),
        })
        capability = str(result.get("capability", ""))
        if not capability:
            raise ServiceClientError("Service không cấp capability.")
        return capability

    def protected(self, action: str, resource: str, **fields) -> dict:
        capability = self.issue_capability(resource)
        return self.call({
            "action": str(action),
            "capability": capability,
            **fields,
        })
