"""Fail-closed NTFS Folder Lock with encrypted DACL backups.

Folder Lock is an ACL boundary, not encryption.  The original DACL is saved
before any deny ACE is applied and is restored verbatim on unlock.  The module
uses Windows security APIs directly; it never shells out to a command
interpreter for ACL changes.
"""

from __future__ import annotations

import base64
import os
import sys
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from .secure_storage import AppCrypto
from .security import is_within, reject_symlink

try:
    import win32api
    import win32con
    import win32security
except ImportError:  # pragma: no cover - exercised on non-Windows hosts.
    win32api = None
    win32con = None
    win32security = None


class FolderLockError(RuntimeError):
    """Raised when Folder Lock cannot complete safely."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _encode_sddl(sddl: str) -> str:
    return base64.b64encode(sddl.encode("utf-8")).decode("ascii")


def _decode_sddl(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise FolderLockError("Bản sao DACL không hợp lệ.")
    try:
        sddl = base64.b64decode(value.encode("ascii"), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise FolderLockError("Bản sao DACL bị hỏng.") from exc
    if not sddl.startswith("D:"):
        raise FolderLockError("Bản sao DACL không đúng định dạng Windows.")
    return sddl


class FolderLockManager:
    FORMAT_VERSION = 1

    def __init__(self, data_root: Path, crypto: AppCrypto | None = None):
        self.data_root = Path(data_root).resolve(strict=False)
        self.path = self.data_root / "folder_locks.json"
        self.crypto = crypto or AppCrypto(self.data_root)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict:
        default = {"format_version": self.FORMAT_VERSION, "locks": {}}
        if not self.path.exists():
            self.crypto.write_json(self.path, default)
            return default
        try:
            saved, encrypted = self.crypto.read_json(self.path)
        except (OSError, ValueError) as exc:
            raise FolderLockError("Không thể đọc danh sách Folder Lock an toàn.") from exc
        data = deepcopy(default)
        if isinstance(saved, dict):
            data.update(saved)
        if not isinstance(data.get("locks"), dict):
            raise FolderLockError("Danh sách Folder Lock bị hỏng.")
        if not encrypted:
            self.crypto.write_json(self.path, data)
        return data

    def _save(self) -> None:
        self._data["format_version"] = self.FORMAT_VERSION
        self._data["updated_at"] = _now()
        self.crypto.write_json(self.path, self._data)

    @staticmethod
    def _require_windows() -> None:
        if sys.platform != "win32" or win32security is None or win32con is None:
            raise FolderLockError("Folder Lock ACL chỉ hỗ trợ trên Windows với quyền quản trị.")

    @staticmethod
    def _current_sid() -> tuple[object, str]:
        FolderLockManager._require_windows()
        try:
            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            try:
                sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            finally:
                win32api.CloseHandle(token)
            return sid, win32security.ConvertSidToStringSid(sid)
        except (OSError, win32security.error) as exc:
            raise FolderLockError("Không xác định được SID tài khoản Windows hiện tại.") from exc

    def _validate_folder(self, path: str | Path) -> Path:
        candidate = reject_symlink(Path(path).expanduser(), "Không khóa symbolic link.")
        if not candidate.is_dir():
            raise FolderLockError("Folder Lock chỉ áp dụng cho một thư mục đang tồn tại.")
        folder = candidate.resolve(strict=True)
        if folder == Path(folder.anchor):
            raise FolderLockError("Không cho phép khóa thư mục gốc của ổ đĩa.")
        # Never lock the app data itself or an ancestor containing it; doing so
        # could prevent FileSentry from reading its own recovery metadata.
        if is_within(folder, self.data_root) or is_within(self.data_root, folder):
            raise FolderLockError("Không thể khóa thư mục dữ liệu hoặc thư mục chứa dữ liệu FileSentry.")
        return folder

    @staticmethod
    def _security_descriptor(path: Path):
        FolderLockManager._require_windows()
        try:
            descriptor = win32security.GetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
            )
            dacl = descriptor.GetSecurityDescriptorDacl()
            sddl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                descriptor, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION
            )
            control = descriptor.GetSecurityDescriptorControl()[0]
            protected = bool(control & win32security.SE_DACL_PROTECTED)
            return sddl, dacl, protected, dacl is not None
        except (OSError, win32security.error) as exc:
            raise FolderLockError(f"Không thể đọc DACL của thư mục: {path}") from exc

    @staticmethod
    def _set_dacl(path: Path, dacl, protected: bool, dacl_present: bool = True) -> None:
        FolderLockManager._require_windows()
        flags = win32security.DACL_SECURITY_INFORMATION
        if protected:
            flags |= win32security.PROTECTED_DACL_SECURITY_INFORMATION
        else:
            flags |= win32security.UNPROTECTED_DACL_SECURITY_INFORMATION
        target_dacl = dacl if dacl_present else None
        try:
            win32security.SetNamedSecurityInfo(
                str(path), win32security.SE_FILE_OBJECT, flags, None, None, target_dacl, None
            )
        except (OSError, win32security.error) as exc:
            raise FolderLockError(f"Không thể khôi phục ACL của thư mục: {path}") from exc

    @staticmethod
    def _dacl_from_sddl(sddl: str):
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            sddl, win32security.SDDL_REVISION_1
        )
        return descriptor.GetSecurityDescriptorDacl()

    @staticmethod
    def _has_owned_deny(dacl, sid) -> bool:
        if dacl is None:
            return False
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            ace_type = ace[0][0] if isinstance(ace[0], tuple) else ace[0]
            ace_sid = ace[-1]
            if ace_type == win32security.ACCESS_DENIED_ACE_TYPE and ace_sid == sid:
                return True
        return False

    @staticmethod
    def _public(item: dict) -> dict:
        return {
            "id": item.get("id"),
            "original_path": item.get("original_path"),
            "owner_sid": item.get("owner_sid"),
            "locked_at": item.get("locked_at"),
            "unlocked_at": item.get("unlocked_at"),
            "status": item.get("status"),
        }

    @property
    def data(self) -> dict:
        return deepcopy(self._data)

    def list_locks(self) -> list[dict]:
        return sorted(
            (self._public(item) for item in self._data["locks"].values()),
            key=lambda item: item.get("locked_at", ""),
            reverse=True,
        )

    def get(self, lock_id: str) -> dict:
        try:
            uuid.UUID(str(lock_id))
        except (ValueError, AttributeError):
            raise FolderLockError("Mã Folder Lock không hợp lệ.")
        item = self._data["locks"].get(str(lock_id))
        if not item:
            raise FolderLockError("Không tìm thấy Folder Lock.")
        return dict(item)

    def lock_folder(self, path: str | Path) -> dict:
        folder = self._validate_folder(path)
        sid, sid_text = self._current_sid()
        normalized = os.path.normcase(str(folder))
        for existing in self._data["locks"].values():
            if os.path.normcase(str(existing.get("original_path", ""))) == normalized and existing.get("status") == "locked":
                raise FolderLockError("Thư mục này đã được khóa.")

        original_sddl, original_dacl, protected, dacl_present = self._security_descriptor(folder)
        lock_id = next(
            (key for key, value in self._data["locks"].items()
             if os.path.normcase(str(value.get("original_path", ""))) == normalized and value.get("status") == "unlocked"),
            uuid.uuid4().hex,
        )
        entry = {
            "id": lock_id,
            "original_path": str(folder),
            "owner_sid": sid_text,
            "original_dacl": _encode_sddl(original_sddl),
            "original_dacl_protected": protected,
            "original_dacl_present": dacl_present,
            "locked_at": _now(),
            "unlocked_at": None,
            "status": "locked",
        }
        self._data["locks"][lock_id] = entry
        # The encrypted atomic manifest is committed before touching NTFS ACL.
        try:
            self._save()
        except Exception as exc:
            self._data["locks"].pop(lock_id, None)
            raise FolderLockError("Không lưu được bản sao DACL; thư mục chưa bị khóa.") from exc

        try:
            if original_dacl is None:
                original_dacl = win32security.ACL()
            original_dacl.AddAccessDeniedAceEx(
                win32security.ACL_REVISION_DS,
                win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE,
                win32con.GENERIC_ALL,
                sid,
            )
            self._set_dacl(folder, original_dacl, protected, True)
        except Exception as exc:
            try:
                self._set_dacl(folder, self._dacl_from_sddl(original_sddl), protected, dacl_present)
                self._data["locks"].pop(lock_id, None)
                self._save()
            except Exception as rollback_exc:
                raise FolderLockError(
                    "ACL không áp dụng được và không thể rollback an toàn; Folder Lock vẫn được giữ để khôi phục thủ công."
                ) from rollback_exc
            raise FolderLockError("Không thể áp dụng ACL khóa; thư mục chưa được giữ ở trạng thái khóa.") from exc
        return self._public(entry)

    def unlock_folder(self, lock_id: str) -> dict:
        item = self.get(lock_id)
        if item.get("status") == "unlocked":
            return self._public(item)
        folder = Path(item.get("original_path", ""))
        if not folder.is_dir() or folder.is_symlink():
            raise FolderLockError(f"Không thể mở khóa vì thư mục không còn tồn tại: {folder}")
        original_sddl = _decode_sddl(item.get("original_dacl", ""))
        original_dacl = self._dacl_from_sddl(original_sddl)
        self._set_dacl(
            folder,
            original_dacl,
            bool(item.get("original_dacl_protected", False)),
            bool(item.get("original_dacl_present", True)),
        )
        item["status"] = "unlocked"
        item["unlocked_at"] = _now()
        self._data["locks"][str(lock_id)] = item
        try:
            self._save()
        except Exception as exc:
            # Do not leave an unlocked folder recorded as unlocked only in RAM.
            try:
                _, current_dacl, protected, _ = self._security_descriptor(folder)
                if current_dacl is None:
                    current_dacl = win32security.ACL()
                _, sid_text = self._current_sid()
                sid = win32security.ConvertStringSidToSid(sid_text)
                current_dacl.AddAccessDeniedAceEx(
                    win32security.ACL_REVISION_DS,
                    win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE,
                    win32con.GENERIC_ALL,
                    sid,
                )
                self._set_dacl(folder, current_dacl, protected, True)
            except Exception as rollback_exc:
                raise FolderLockError(
                    "Đã khôi phục DACL nhưng không lưu được trạng thái; cần kiểm tra Folder Lock trước khi tiếp tục."
                ) from rollback_exc
            raise FolderLockError("Không lưu được trạng thái mở khóa an toàn.") from exc
        return self._public(item)

    def verify_lock_integrity(self) -> list[dict]:
        findings: list[dict] = []
        if sys.platform != "win32" or win32security is None:
            if any(item.get("status") == "locked" for item in self._data["locks"].values()):
                findings.append({"severity": "critical", "issue": "windows_acl_unavailable"})
            return findings
        sid, sid_text = self._current_sid()
        for lock_id, item in self._data["locks"].items():
            folder = Path(item.get("original_path", ""))
            if not folder.is_dir() or folder.is_symlink():
                findings.append({"severity": "critical", "lock_id": lock_id, "path": str(folder), "issue": "target_missing"})
                continue
            try:
                actual_sddl, actual_dacl, protected, dacl_present = self._security_descriptor(folder)
                if item.get("status") == "locked":
                    if not self._has_owned_deny(actual_dacl, sid):
                        findings.append({"severity": "critical", "lock_id": lock_id, "path": str(folder), "issue": "locked_status_without_owned_deny", "owner_sid": sid_text})
                else:
                    expected_sddl = _decode_sddl(item.get("original_dacl", ""))
                    if actual_sddl != expected_sddl or protected != bool(item.get("original_dacl_protected", False)) or dacl_present != bool(item.get("original_dacl_present", True)):
                        findings.append({"severity": "critical", "lock_id": lock_id, "path": str(folder), "issue": "unlocked_acl_does_not_match_backup"})
            except (FolderLockError, OSError) as exc:
                findings.append({"severity": "critical", "lock_id": lock_id, "path": str(folder), "issue": "acl_read_failed", "error": str(exc)})
        return findings

    def unlock_all_for_uninstall(self) -> dict:
        failures: list[dict] = []
        unlocked: list[str] = []
        for lock_id, item in list(self._data["locks"].items()):
            if item.get("status") != "locked":
                continue
            try:
                self.unlock_folder(lock_id)
                unlocked.append(lock_id)
            except FolderLockError as exc:
                failures.append({"lock_id": lock_id, "path": item.get("original_path"), "error": str(exc)})
        findings = self.verify_lock_integrity()
        if failures or findings:
            details = failures + findings
            raise FolderLockError("Chưa thể gỡ an toàn; các Folder Lock chưa xác minh được: " + "; ".join(str(item.get("path", item.get("lock_id", "unknown"))) for item in details))
        return {"unlocked": unlocked, "failures": [], "verified": True}
