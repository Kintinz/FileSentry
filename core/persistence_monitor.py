"""Read-only Windows persistence inventory and change detection."""

from __future__ import annotations

import csv
import io
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable


WRITABLE_ROOTS = tuple(
    value for value in (
        os.environ.get("TEMP"),
        os.environ.get("TMP"),
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    ) if value
)


def _is_user_writable(value: str) -> bool:
    expanded = os.path.expandvars(str(value)).strip().strip('"')
    normalized = os.path.normcase(expanded)
    return any(root and os.path.normcase(root) in normalized for root in WRITABLE_ROOTS)


class PersistenceMonitor:
    def __init__(self, callback: Callable[[dict], None], interval: float = 30.0):
        self.callback = callback
        self.interval = max(10.0, interval)
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self._known: dict[str, dict] = {}
        self._snapshot: list[dict] = []
        self._baseline_ready = False
        self._last_scan = None
        self._last_error = None

    @property
    def backend(self) -> str:
        return "windows-registry+startup+schtasks" if sys.platform == "win32" else "unavailable"

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="FileSentryPersistence", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
        self.thread = None

    def _run(self) -> None:
        while not self.stop_event.is_set():
            self.scan_once()
            self.stop_event.wait(self.interval)

    def _registry_entries(self) -> list[dict]:
        import winreg

        paths = (
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        )
        entries = []
        for root, path, label in paths:
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for index in range(count):
                        name, value, _value_type = winreg.EnumValue(key, index)
                        command = str(value)
                        entries.append(self._entry("registry", f"{label}:{name}", command, path))
            except (FileNotFoundError, PermissionError, OSError):
                continue
        return entries

    def _startup_entries(self) -> list[dict]:
        roots = (
            Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
            Path(os.environ.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        )
        entries = []
        for root in roots:
            if not root.exists():
                continue
            try:
                for item in root.iterdir():
                    if item.is_file() or item.is_symlink():
                        entries.append(self._entry("startup_folder", item.name, str(item), str(root)))
            except OSError:
                continue
        return entries

    def _service_entries(self) -> list[dict]:
        import winreg

        root_path = r"SYSTEM\CurrentControlSet\Services"
        entries = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path, 0, winreg.KEY_READ) as root:
                count = winreg.QueryInfoKey(root)[0]
                for index in range(count):
                    try:
                        name = winreg.EnumKey(root, index)
                        with winreg.OpenKey(root, name, 0, winreg.KEY_READ) as service:
                            image_path, _value_type = winreg.QueryValueEx(service, "ImagePath")
                        entries.append(self._entry("service", name, str(image_path), f"HKLM\\{root_path}\\{name}"))
                    except (FileNotFoundError, PermissionError, OSError):
                        continue
        except (FileNotFoundError, PermissionError, OSError):
            return []
        return entries

    def _scheduled_tasks(self) -> list[dict]:
        try:
            result = subprocess.run(
                ["schtasks.exe", "/Query", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        entries = []
        for row in csv.reader(io.StringIO(result.stdout)):
            if not row or not row[0].strip() or row[0].strip().lower() in {"info: no tasks are running", "error:"}:
                continue
            name = row[0].strip()
            if name.startswith("\\"):
                entries.append(self._entry("scheduled_task", name, "", "schtasks"))
        return entries

    @staticmethod
    def _entry(kind: str, name: str, command: str, location: str) -> dict:
        risks = []
        if command and _is_user_writable(command):
            risks.append({"code": "writable_persistence", "title": "Persistence trỏ vào thư mục người dùng", "severity": "warning"})
        return {
            "kind": kind,
            "name": name,
            "command": command,
            "location": location,
            "risks": risks,
        }

    @staticmethod
    def _key(entry: dict) -> str:
        return "|".join(str(entry.get(key, "")) for key in ("kind", "name", "command", "location"))

    def scan_once(self) -> list[dict]:
        if sys.platform != "win32":
            return []
        try:
            entries = self._registry_entries() + self._startup_entries() + self._scheduled_tasks() + self._service_entries()
            error = None
        except Exception as exc:
            entries = []
            error = str(exc)
        current = {self._key(entry): entry for entry in entries}
        with self.lock:
            previous = self._known
            baseline_ready = self._baseline_ready
            self._known = current
            self._snapshot = entries
            self._last_scan = time.time()
            self._last_error = error
            self._baseline_ready = True
        if baseline_ready:
            for key, entry in current.items():
                if key not in previous:
                    self.callback({"event_type": "persistence_added", "path": f"persistence://{entry['kind']}/{entry['name']}", "source": "persistence_monitor", "details": entry, "risks": entry["risks"]})
            for key, entry in previous.items():
                if key not in current:
                    self.callback({"event_type": "persistence_removed", "path": f"persistence://{entry['kind']}/{entry['name']}", "source": "persistence_monitor", "details": entry, "risks": []})
        return entries

    def snapshot(self) -> list[dict]:
        with self.lock:
            return [dict(entry, risks=list(entry.get("risks", []))) for entry in self._snapshot]

    def status(self) -> dict:
        with self.lock:
            return {"backend": self.backend, "running": bool(self.thread and self.thread.is_alive()), "last_scan": self._last_scan, "last_error": self._last_error, "count": len(self._snapshot)}
