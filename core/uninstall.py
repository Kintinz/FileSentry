"""Safe two-phase self-uninstall for the packaged Windows executable."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .paths import DATA_DIR
from .security import atomic_write_bytes, is_within


class UninstallError(RuntimeError):
    pass


_CLEANUP_SCRIPT = r'''param(
    [Parameter(Mandatory=$true)][int]$ProcessId,
    [Parameter(Mandatory=$true)][string]$ExecutablePath,
    [Parameter(Mandatory=$false)][string]$DataPath
)

$ErrorActionPreference = "SilentlyContinue"
try { Wait-Process -Id $ProcessId -Timeout 30 } catch {}
Start-Sleep -Seconds 2

$executable = [IO.Path]::GetFullPath($ExecutablePath)
$targets = @($executable)
if (-not [string]::IsNullOrWhiteSpace($DataPath)) {
    $data = [IO.Path]::GetFullPath($DataPath)
    if ([IO.Path]::GetFileName($data) -ieq "FileSentry" -and $data -ne [IO.Path]::GetPathRoot($data)) {
        $targets += $data
    }
}

foreach ($target in $targets) {
    if ([string]::IsNullOrWhiteSpace($target)) { continue }
    $full = [IO.Path]::GetFullPath($target)
    if ($full -eq [IO.Path]::GetPathRoot($full)) { continue }
    if (Test-Path -LiteralPath $full -PathType Leaf) {
        Remove-Item -LiteralPath $full -Force
    } elseif (Test-Path -LiteralPath $full -PathType Container -and [IO.Path]::GetFileName($full) -ieq "FileSentry") {
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

Remove-Item -LiteralPath $PSCommandPath -Force
'''


class UninstallManager:
    """Validate exact targets and ask a detached helper to remove them later."""

    def __init__(self, data_path: Path | None = None):
        self.data_path = Path(data_path or DATA_DIR).resolve(strict=False)

    @staticmethod
    def executable_path() -> Path:
        if sys.platform != "win32" or not getattr(sys, "frozen", False):
            raise UninstallError("Chỉ bản EXE đóng gói mới được phép tự gỡ.")
        executable = Path(sys.executable).resolve(strict=True)
        if executable.name.lower() not in {"filesentry.exe", "filesentrysentinel.exe"} or not executable.is_file():
            raise UninstallError("Không xác định được FileSentry.exe hợp lệ để gỡ.")
        return executable

    def validate_data_target(self) -> Path:
        target = self.data_path
        if target.name.lower() != "filesentry":
            raise UninstallError("Từ chối xóa: thư mục dữ liệu không có tên FileSentry.")
        if target == Path(target.anchor):
            raise UninstallError("Từ chối xóa thư mục gốc của ổ đĩa.")
        project_root = Path(__file__).resolve().parents[1]
        if target == project_root or is_within(project_root, target):
            raise UninstallError("Từ chối xóa thư mục dự án hoặc thư mục chứa dự án.")
        return target

    def release_folder_locks(self, folder_lock_manager, audit_callback=None) -> dict:
        """Release every ACL Folder Lock before the uninstall confirmation.

        The callback is invoked before and after each release so the caller can
        persist audit evidence while the encrypted application data still
        exists.  Any failure is converted to ``UninstallError`` and blocks the
        cleanup helper from being scheduled.
        """
        locked = [item for item in folder_lock_manager.list_locks() if item.get("status") == "locked"]
        for item in locked:
            if audit_callback:
                audit_callback("folder_lock_auto_unlock_started", {"lock_id": item.get("id"), "path": item.get("original_path")})
        try:
            result = folder_lock_manager.unlock_all_for_uninstall()
        except Exception as exc:
            if audit_callback:
                audit_callback("folder_lock_auto_unlock_failed", {"error": str(exc)})
            raise UninstallError(
                "Chưa thể gỡ FileSentry: một hoặc nhiều thư mục ACL chưa được mở khóa an toàn. "
                "Không có dữ liệu nào bị xóa."
            ) from exc
        findings = folder_lock_manager.verify_lock_integrity()
        if findings:
            if audit_callback:
                audit_callback("folder_lock_integrity_failed_before_uninstall", {"findings": findings})
            raise UninstallError(
                "Chưa thể gỡ FileSentry: kiểm tra ACL sau khi mở khóa vẫn còn cảnh báo. Không có dữ liệu nào bị xóa."
            )
        if audit_callback:
            for lock_id in result.get("unlocked", []):
                audit_callback("folder_lock_auto_unlocked", {"lock_id": lock_id})
            audit_callback("folder_locks_cleared_for_uninstall", {"count": len(result.get("unlocked", []))})
        return result

    def schedule(self, delete_data: bool) -> None:
        executable = self.executable_path()
        data_path = self.validate_data_target() if delete_data else None
        script_path = Path(tempfile.gettempdir()) / f"filesentry-uninstall-{os.getpid()}.ps1"
        atomic_write_bytes(script_path, _CLEANUP_SCRIPT.encode("utf-8"))
        try:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
            subprocess.Popen(
                [
                    str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
                    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-File", str(script_path),
                    "-ProcessId", str(os.getpid()),
                    "-ExecutablePath", str(executable),
                    "-DataPath", str(data_path) if data_path else "",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags,
                close_fds=True,
            )
        except OSError as exc:
            script_path.unlink(missing_ok=True)
            raise UninstallError("Không thể khởi động tiến trình gỡ FileSentry.") from exc
