"""Windows-side delete protection for individual media files.

Only the explicit ``DELETE`` deny ACE owned by FileSentry is added or removed.
The rest of the file DACL is preserved.  Changes use the Windows security API
directly so removing protection does not depend on shell output or reset the
user's other permissions.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .security import reject_symlink

try:
    import win32api
    import win32con
    import win32security
except ImportError:  # pragma: no cover - exercised on non-Windows hosts.
    win32api = None
    win32con = None
    win32security = None


class MediaProtectionError(RuntimeError):
    pass


class MediaFileProtection:
    """Manage only FileSentry's per-file delete deny ACE."""

    def __init__(self, principal: str | None = None):
        self.principal = principal or self._current_principal()

    @staticmethod
    def _current_principal() -> str:
        username = os.environ.get("USERNAME")
        if not username or any(character in username for character in ";()\"\n\r"):
            raise MediaProtectionError("Không xác định được tài khoản Windows hiện tại.")
        domain = os.environ.get("USERDOMAIN") or os.environ.get("COMPUTERNAME") or "."
        if any(character in domain for character in ";()\"\n\r"):
            raise MediaProtectionError("Tên miền Windows không hợp lệ.")
        return f"{domain}\\{username}"

    @staticmethod
    def _require_windows() -> None:
        if sys.platform != "win32" or win32security is None or win32con is None or win32api is None:
            raise MediaProtectionError("Khóa xóa file chỉ hỗ trợ trên Windows.")

    @staticmethod
    def _validate(path: str | Path) -> Path:
        candidate = reject_symlink(Path(path).expanduser())
        if not candidate.is_file():
            raise MediaProtectionError("File media không còn tồn tại.")
        # Avoid strict resolve performing a second permission-sensitive stat.
        return Path(os.path.abspath(str(candidate)))

    @classmethod
    def _current_sid(cls):
        cls._require_windows()
        try:
            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            try:
                return win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            finally:
                win32api.CloseHandle(token)
        except (OSError, win32security.error) as exc:
            raise MediaProtectionError("Không xác định được SID tài khoản Windows hiện tại.") from exc

    @classmethod
    def _security_descriptor(cls, path: Path):
        cls._require_windows()
        try:
            descriptor = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
            )
            dacl = descriptor.GetSecurityDescriptorDacl()
            control = descriptor.GetSecurityDescriptorControl()[0]
            protected = bool(control & win32security.SE_DACL_PROTECTED)
            return dacl, protected, dacl is not None
        except (OSError, win32security.error) as exc:
            raise MediaProtectionError(f"Không thể đọc quyền bảo vệ của file: {path}") from exc

    @classmethod
    def _set_dacl(cls, path: Path, dacl, protected: bool, dacl_present: bool) -> None:
        cls._require_windows()
        flags = win32security.DACL_SECURITY_INFORMATION
        flags |= (
            win32security.PROTECTED_DACL_SECURITY_INFORMATION
            if protected
            else win32security.UNPROTECTED_DACL_SECURITY_INFORMATION
        )
        try:
            win32security.SetNamedSecurityInfo(
                str(path),
                win32security.SE_FILE_OBJECT,
                flags,
                None,
                None,
                dacl if dacl_present else None,
                None,
            )
        except (OSError, win32security.error) as exc:
            error_code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            if error_code == 5:
                raise MediaProtectionError(
                    "Windows từ chối sửa quyền file. Hãy đóng ứng dụng đang giữ file và chạy FileSentry bằng Administrator."
                ) from exc
            raise MediaProtectionError(f"Không thể cập nhật quyền bảo vệ của file: {path}") from exc

    @classmethod
    def _is_owned_delete_deny(cls, ace, sid) -> bool:
        try:
            ace_type = ace[0][0] if isinstance(ace[0], tuple) else ace[0]
            mask = int(ace[1])
            ace_sid = ace[-1]
        except (IndexError, TypeError, ValueError):
            return False
        delete_mask = int(win32con.DELETE)
        return (
            ace_type == win32security.ACCESS_DENIED_ACE_TYPE
            and ace_sid == sid
            and mask in {delete_mask, delete_mask | int(getattr(win32con, "SYNCHRONIZE", 0))}
        )

    @classmethod
    def _has_owned_delete_deny(cls, dacl, sid) -> bool:
        if dacl is None:
            return False
        return any(cls._is_owned_delete_deny(dacl.GetAce(index), sid) for index in range(dacl.GetAceCount()))

    @classmethod
    def _remove_owned_delete_denies(cls, dacl, sid) -> int:
        if dacl is None:
            return 0
        removed = 0
        for index in range(dacl.GetAceCount() - 1, -1, -1):
            if cls._is_owned_delete_deny(dacl.GetAce(index), sid):
                dacl.DeleteAce(index)
                removed += 1
        return removed

    def set_delete_protected(self, path: str | Path, enabled: bool) -> None:
        candidate = self._validate(path)
        sid = self._current_sid()
        dacl, protected, dacl_present = self._security_descriptor(candidate)
        if enabled:
            if dacl is None:
                dacl = win32security.ACL()
                dacl_present = True
            if not self._has_owned_delete_deny(dacl, sid):
                dacl.AddAccessDeniedAceEx(win32security.ACL_REVISION_DS, 0, win32con.DELETE, sid)
            self._set_dacl(candidate, dacl, protected, dacl_present)
            return

        if dacl is None or not self._remove_owned_delete_denies(dacl, sid):
            return
        self._set_dacl(candidate, dacl, protected, dacl_present)
        verify_dacl, _verify_protected, _verify_present = self._security_descriptor(candidate)
        if self._has_owned_delete_deny(verify_dacl, sid):
            raise MediaProtectionError("Windows chưa gỡ được deny ACE của FileSentry; file vẫn đang được bảo vệ.")
