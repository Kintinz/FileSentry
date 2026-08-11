"""Headless agent host used as the V2 service boundary."""

from __future__ import annotations

import threading
from collections.abc import Callable


class AgentHost:
    """Run the existing controller without creating a Tkinter UI.

    The controller still uses the configured Windows identity/data profile. A
    production SYSTEM service must use a dedicated service data/IPC design;
    this host intentionally does not silently install or impersonate one.
    """

    def __init__(self, controller_factory: Callable[[], object]):
        self.controller_factory = controller_factory
        self.controller = None
        self.stop_event = threading.Event()

    def start(self) -> None:
        if self.controller is not None:
            return
        self.controller = self.controller_factory()
        self.stop_event.clear()

    def stop(self) -> None:
        self.stop_event.set()
        if self.controller is not None:
            self.controller.stop()
            self.controller = None

    def wait(self, timeout: float | None = None) -> bool:
        return self.stop_event.wait(timeout)
