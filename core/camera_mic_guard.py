"""Watch-and-revert enforcement for managed camera/microphone policy."""

from __future__ import annotations

import sys
import threading
import time
from typing import Callable

from .media_guard import MediaGuardError, WindowsPrivacyAdapter


class CameraMicGuard:
    """Re-apply deny when a managed device is opened without an app grant.

    Windows does not provide a user-mode pre-hook for every privacy toggle. This
    component therefore documents and implements the realistic watch-and-revert
    model: it polls policy, reverts unauthorized Allow states, and emits an
    audit event with the observed exposure window.
    """

    DEVICES = ("camera", "microphone")

    def __init__(
        self,
        adapter: WindowsPrivacyAdapter,
        gateway,
        managed: Callable[[str], bool],
        callback: Callable[[dict], None],
        interval: float = 3.0,
    ):
        self.adapter = adapter
        self.gateway = gateway
        self.managed = managed
        self.callback = callback
        self.interval = max(2.0, float(interval))
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self._last_policy: dict[str, dict | None] = {}
        self._opened_at: dict[str, float | None] = {device: None for device in self.DEVICES}
        self._last_failure: dict[str, float] = {}
        self._revert_alerts: dict[str, dict[str, float]] = {
            device: {"count": 0.0, "last_emitted": 0.0} for device in self.DEVICES
        }

    def start(self) -> None:
        if sys.platform != "win32" or (self.thread and self.thread.is_alive()):
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="FileSentryMediaGuard", daemon=True)
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

    def scan_once(self) -> None:
        if sys.platform != "win32":
            return
        now = time.monotonic()
        for device in self.DEVICES:
            if not self.managed(device):
                continue
            try:
                policy = self.adapter.read_policy(device)
            except MediaGuardError as exc:
                self._emit_failure(device, str(exc), now)
                continue
            previous = self._last_policy.get(device)
            self._last_policy[device] = policy
            denied = self.adapter.is_force_denied(policy)
            granted = self.gateway.is_unlocked(device)
            if denied:
                self._opened_at[device] = None
                continue
            if granted:
                self._opened_at[device] = None
                continue
            if self._opened_at[device] is None:
                self._opened_at[device] = now
            try:
                self.adapter.apply_force_deny(device)
            except MediaGuardError as exc:
                self._emit_failure(device, str(exc), now)
                continue
            exposure = max(0, int(now - (self._opened_at[device] or now)))
            self._opened_at[device] = None
            alert_recommended, alert_count = self._revert_alert_decision(device, now)
            self.callback({
                "event_type": "unauthorized_media_access_reverted",
                "path": f"media://{device}",
                "source": "camera_mic_guard",
                "details": {
                    "device": device,
                    "previous_policy": previous,
                    "observed_exposure_seconds": exposure,
                    "action": "force_deny_reapplied",
                    "alert_recommended": alert_recommended,
                    "alert_count": alert_count,
                },
            })

    def _revert_alert_decision(self, device: str, now: float) -> tuple[bool, int]:
        """Keep every revert as an event while throttling visible alerts."""

        state = self._revert_alerts[device]
        state["count"] += 1
        if now - state["last_emitted"] < 10.0:
            return False, int(state["count"])
        count = int(state["count"])
        state["count"] = 0.0
        state["last_emitted"] = now
        return True, count

    def _emit_failure(self, device: str, message: str, now: float) -> None:
        if now - self._last_failure.get(device, 0) < 60:
            return
        self._last_failure[device] = now
        self.callback({
            "event_type": "media_guard_enforcement_failed",
            "path": f"media://{device}",
            "source": "camera_mic_guard",
            "details": {"device": device, "error": message},
        })
