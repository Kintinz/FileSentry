"""Provisioning for the encrypted UI/Service IPC secret."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from core.secure_storage import AppCrypto
from core.security import reject_symlink

from .named_pipe import current_user_sid
from .windows_acl import harden_ipc_material_acl


class IpcMaterialError(RuntimeError):
    pass


class IpcSecretStore:
    """Store the transport secret encrypted with machine-scope DPAPI.

    Provisioning is an explicit interactive action. A SYSTEM service may load
    an existing secret but never silently create a new one, which prevents a
    service restart from creating an IPC endpoint the UI cannot authenticate.
    """

    def __init__(self, root: str | Path | None = None):
        if root is None:
            root = Path(os.environ.get("FILESENTRY_IPC_DIR", ""))
            if not str(root):
                root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "FileSentry" / "IPC"
        self.root = Path(root).expanduser()
        self.path = self.root / "secret.json"
        self.crypto = AppCrypto(self.root, dpapi_scope="machine")

    def provision(self) -> dict:
        if self.path.exists():
            raise IpcMaterialError("IPC secret đã tồn tại; không ghi đè tự động.")
        secret = os.urandom(32)
        self.crypto.write_json(self.path, {"version": 1, "secret": base64.b64encode(secret).decode("ascii")})
        harden_ipc_material_acl(self.root, current_user_sid())
        return {"path": str(self.path), "user_sid": current_user_sid()}

    def load(self) -> bytes:
        reject_symlink(self.path, "IPC secret không được là symbolic link.")
        if not self.path.exists():
            raise IpcMaterialError("Chưa provision IPC secret; Service không được tự tạo secret.")
        payload, encrypted = self.crypto.read_json(self.path)
        if not encrypted or payload.get("version") != 1:
            raise IpcMaterialError("IPC secret phải ở định dạng mã hóa hợp lệ.")
        try:
            secret = base64.b64decode(str(payload["secret"]), validate=True)
        except Exception as exc:
            raise IpcMaterialError("IPC secret không hợp lệ.") from exc
        if len(secret) < 32:
            raise IpcMaterialError("IPC secret quá ngắn.")
        return secret
