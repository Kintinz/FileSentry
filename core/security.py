"""Small security primitives shared by the FileSentry core.

These helpers are deliberately local and dependency-light.  They do not try to
replace Windows ACLs or a kernel enforcement component; they make the V1 data
path safer against accidental disclosure, symlink tricks and partial writes.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path


def ensure_private_directory(path: Path) -> None:
    """Create a directory and apply the narrowest portable local permission."""

    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        try:
            path.chmod(0o700)
        except OSError:
            pass


def ensure_private_file(path: Path) -> None:
    """Best-effort owner-only permission for non-Windows development hosts."""

    if sys.platform != "win32" and Path(path).exists():
        try:
            Path(path).chmod(0o600)
        except OSError:
            pass


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Write bytes without exposing a partially-written target file."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Không ghi dữ liệu vào đường dẫn symbolic link.")

    temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(str(temporary), flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        os.replace(temporary, path)
        ensure_private_file(path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def reject_symlink(path: Path, message: str = "Không chấp nhận symbolic link.") -> Path:
    """Reject a symlink before a security-sensitive file operation."""

    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(message)
    return candidate


def is_within(path: Path, root: Path) -> bool:
    """Return whether *path* is inside *root* after canonicalization."""

    try:
        Path(path).resolve(strict=False).relative_to(Path(root).resolve(strict=False))
        return True
    except ValueError:
        return False


def harden_windows_acl(path: Path) -> None:
    """Restrict a packaged app's data directory to the current user and SYSTEM.

    Development runs intentionally do not rewrite workspace ACLs.  The packaged
    build calls this only for its dedicated ProgramData directory.
    """

    if sys.platform != "win32":
        return
    username = os.environ.get("USERNAME")
    if not username:
        raise RuntimeError("Không xác định được tài khoản Windows để bảo vệ dữ liệu.")
    domain = os.environ.get("USERDOMAIN") or os.environ.get("COMPUTERNAME") or "."
    account = f"{domain}\\{username}"
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    icacls = Path(system_root) / "System32" / "icacls.exe"
    result = subprocess.run(
        [
            str(icacls), str(path), "/inheritance:r",
            "/grant:r", f"{account}:(OI)(CI)F",
            "/grant:r", "SYSTEM:(OI)(CI)F",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise RuntimeError("Không thể thiết lập ACL an toàn cho thư mục dữ liệu FileSentry.")
