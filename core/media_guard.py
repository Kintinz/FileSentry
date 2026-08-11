"""Windows privacy-policy adapter for camera and microphone controls.

The adapter is intentionally conservative: deny changes are made only when the
user clicks an authenticated action and confirms the warning. It updates both
the Windows-app policy and the current user's unpackaged-desktop-app consent,
because browsers and other desktop applications use the latter layer.
Website-level allowlists are stored by origin for the future browser extension;
Windows privacy policy itself cannot distinguish the URL inside a browser.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


class MediaGuardError(RuntimeError):
    pass


class WindowsPrivacyAdapter:
    POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    CONSENT_STORE_PATH = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    VALUE_NAMES = {
        "camera": "LetAppsAccessCamera",
        "microphone": "LetAppsAccessMicrophone",
    }
    SETTINGS_URIS = {
        "camera": "ms-settings:privacy-webcam",
        "microphone": "ms-settings:privacy-microphone",
    }

    def _validate_kind(self, kind: str) -> str:
        if kind not in self.VALUE_NAMES:
            raise MediaGuardError(f"Thiết bị media không hợp lệ: {kind}")
        return kind

    def _read_app_policy(self, kind: str) -> int | None:
        kind = self._validate_kind(kind)
        if sys.platform != "win32":
            return None
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.POLICY_PATH, 0, winreg.KEY_READ) as key:
                value, _kind = winreg.QueryValueEx(key, self.VALUE_NAMES[kind])
                return int(value)
        except FileNotFoundError:
            return None
        except PermissionError as exc:
            raise MediaGuardError("Không đủ quyền đọc Windows privacy policy. Hãy chạy FileSentry với quyền Admin.") from exc

    def _read_desktop_policy(self, kind: str) -> str | None:
        kind = self._validate_kind(kind)
        if sys.platform != "win32":
            return None
        import winreg

        path = f"{self.CONSENT_STORE_PATH}\\{kind}\\NonPackaged"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
                value, _value_type = winreg.QueryValueEx(key, "Value")
                return str(value)
        except FileNotFoundError:
            return None
        except PermissionError as exc:
            raise MediaGuardError("Không đủ quyền đọc quyền desktop app của Windows.") from exc

    def read_policy(self, kind: str) -> dict:
        """Read both Windows-app and unpackaged-desktop-app privacy layers."""

        self._validate_kind(kind)
        return {
            "app_policy": self._read_app_policy(kind),
            "desktop_policy": self._read_desktop_policy(kind),
        }

    @staticmethod
    def is_force_denied(policy: dict | None) -> bool:
        return bool(policy and (policy.get("app_policy") == 2 or policy.get("desktop_policy") == "Deny"))

    def _write_desktop_policy(self, kind: str, value: str | None) -> None:
        import winreg

        path = f"{self.CONSENT_STORE_PATH}\\{kind}\\NonPackaged"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            if value is None:
                try:
                    winreg.DeleteValue(key, "Value")
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, value)

    def apply_force_deny(self, kind: str) -> dict:
        kind = self._validate_kind(kind)
        if sys.platform != "win32":
            raise MediaGuardError("Media Guard system policy chỉ được hỗ trợ trên Windows.")
        import winreg

        previous = self.read_policy(kind)
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, self.POLICY_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, self.VALUE_NAMES[kind], 0, winreg.REG_DWORD, 2)
            self._write_desktop_policy(kind, "Deny")
        except PermissionError as exc:
            try:
                self.restore_policy(kind, previous)
            except Exception:
                pass
            raise MediaGuardError("Cần quyền Administrator để khóa thiết bị ở mức hệ thống.") from exc
        except OSError as exc:
            try:
                self.restore_policy(kind, previous)
            except Exception:
                pass
            raise MediaGuardError("Không thể áp dụng đầy đủ policy khóa thiết bị.") from exc
        self.refresh_policy()
        if not self.is_force_denied(self.read_policy(kind)):
            try:
                self.restore_policy(kind, previous)
            except Exception:
                pass
            raise MediaGuardError("Windows chưa xác nhận trạng thái khóa thiết bị.")
        return previous

    def restore_policy(self, kind: str, previous: dict | int | None) -> None:
        kind = self._validate_kind(kind)
        if sys.platform != "win32":
            return
        import winreg

        if isinstance(previous, dict):
            app_previous = previous.get("app_policy")
            desktop_previous = previous.get("desktop_policy")
        else:
            # Backward compatibility for V1 settings that stored only the HKLM value.
            app_previous = previous
            desktop_previous = None
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, self.POLICY_PATH, 0, winreg.KEY_SET_VALUE) as key:
                if app_previous is None:
                    try:
                        winreg.DeleteValue(key, self.VALUE_NAMES[kind])
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(key, self.VALUE_NAMES[kind], 0, winreg.REG_DWORD, int(app_previous))
            self._write_desktop_policy(kind, desktop_previous)
        except PermissionError as exc:
            raise MediaGuardError("Cần quyền Administrator để mở khóa thiết bị ở mức hệ thống.") from exc
        self.refresh_policy()

    @staticmethod
    def refresh_policy() -> None:
        """Ask Windows to refresh computer policy after a policy registry change."""
        if sys.platform != "win32":
            return
        try:
            subprocess.run(
                ["gpupdate.exe", "/target:computer", "/force"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            # The registry policy remains persisted; Windows may apply it at the
            # next policy refresh or reboot if gpupdate is unavailable.
            return

    def open_privacy_settings(self, kind: str) -> None:
        kind = self._validate_kind(kind)
        uri = self.SETTINGS_URIS[kind]
        if sys.platform == "win32":
            os.startfile(uri)
        else:
            raise MediaGuardError("Windows Privacy Settings chỉ có trên Windows.")


def normalize_origin(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Nhập origin hợp lệ, ví dụ https://example.com")
    return f"{parsed.scheme}://{parsed.netloc.lower()}"
