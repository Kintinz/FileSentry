"""Local antivirus/EDR posture check. No network calls."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from typing import Callable


_HEALTH_COMMAND = r'''$d=$null; try {$d=Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,NISEnabled} catch {}; $p=@(); try {$p=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,productState,pathToSignedProductExe)} catch {}; [pscustomobject]@{defender=$d;products=$p} | ConvertTo-Json -Compress -Depth 4'''


def query_antivirus() -> dict:
    if sys.platform != "win32":
        return {"status": "unsupported", "defender": None, "products": [], "checked_at": time.time(), "error": "Windows only"}
    powershell = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    try:
        result = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _HEALTH_COMMAND],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        payload = json.loads(result.stdout.strip() or "{}")
        defender = payload.get("defender")
        products = payload.get("products") or []
        if isinstance(products, dict):
            products = [products]
        if defender and all(bool(defender.get(key)) for key in ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled")):
            status = "protected"
        elif defender:
            status = "warning"
        elif products:
            status = "detected"
        else:
            status = "unknown"
        return {"status": status, "defender": defender, "products": products, "checked_at": time.time(), "error": None if result.returncode == 0 else "PowerShell health query failed"}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {"status": "unknown", "defender": None, "products": [], "checked_at": time.time(), "error": str(exc)}


class SystemHealthMonitor:
    def __init__(self, callback: Callable[[dict], None], interval: float = 60.0):
        self.callback = callback
        self.interval = max(30.0, interval)
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self._state = {"status": "checking", "defender": None, "products": [], "checked_at": None, "error": None}
        self._previous_status = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="FileSentryHealth", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
        self.thread = None

    def _run(self) -> None:
        while not self.stop_event.is_set():
            state = query_antivirus()
            with self.lock:
                previous = self._previous_status
                self._state = state
                self._previous_status = state.get("status")
            if previous is not None and previous != state.get("status") and state.get("status") in {"warning", "unknown"}:
                self.callback({"event_type": "security_health_changed", "path": "security://antivirus", "source": "system_health", "details": state})
            self.stop_event.wait(self.interval)

    def state(self) -> dict:
        with self.lock:
            return dict(self._state)
