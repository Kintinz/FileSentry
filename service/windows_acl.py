"""Windows ACL helpers for the V2 service boundary."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _apply_acl(path: Path, grants: list[str]) -> None:
    if sys.platform != "win32":
        return
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    icacls = Path(system_root) / "System32" / "icacls.exe"
    arguments = [str(icacls), str(path), "/inheritance:r"]
    for grant in grants:
        arguments.extend(["/grant:r", grant])
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise RuntimeError("KhÃ´ng thá»ƒ thiáº¿t láº­p ACL cho profile V2.")


def harden_service_profile_acl(path: Path) -> None:
    """Restrict service data to SYSTEM and the local Administrators group."""

    _apply_acl(Path(path), ["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])


def harden_ipc_material_acl(path: Path, user_sid: str | None = None) -> None:
    """Allow SYSTEM and only the current interactive account to read IPC material."""

    if user_sid:
        if not user_sid.startswith("S-") or any(character in user_sid for character in ";()"):
            raise RuntimeError("Interactive user SID không hợp lệ cho IPC.")
        user_grant = f"*{user_sid}:(OI)(CI)F"
    else:
        username = os.environ.get("USERNAME")
        if not username:
            raise RuntimeError("KhÃ´ng xÃ¡c Ä‘á»‹nh Ä‘Æ°á»£c tÃ i khoáº£n Windows cho IPC.")
        domain = os.environ.get("USERDOMAIN") or os.environ.get("COMPUTERNAME") or "."
        user_grant = f"{domain}\\{username}:(OI)(CI)F"
    _apply_acl(Path(path), ["*S-1-5-18:(OI)(CI)F", user_grant])
