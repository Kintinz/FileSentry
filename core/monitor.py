"""Scoped file monitoring with watchdog when available and polling fallback."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Callable

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # Optional dependency; the MVP remains runnable with polling.
    FileSystemEventHandler = None
    Observer = None


def sha256_for_file(path: Path, max_bytes: int = 32 * 1024 * 1024) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def make_event(event_type: str, path: str, is_dir: bool = False, old_path: str | None = None) -> dict:
    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": event_type,
        "path": str(Path(path)),
        "old_path": old_path,
        "is_dir": is_dir,
        "source": "watchdog" if Observer else "polling",
    }
    if not is_dir:
        try:
            result["size"] = Path(path).stat().st_size
            result["sha256"] = sha256_for_file(Path(path))
        except OSError:
            pass
    return result


class _WatchdogHandler(FileSystemEventHandler if FileSystemEventHandler else object):
    def __init__(self, callback: Callable[[dict], None], in_scope: Callable[[str], bool]):
        super().__init__() if FileSystemEventHandler else None
        self.callback = callback
        self.in_scope = in_scope

    def _emit(self, event_type: str, path: str, is_dir: bool = False, old_path: str | None = None) -> None:
        if self.in_scope(path) or (old_path and self.in_scope(old_path)):
            self.callback(make_event(event_type, path, is_dir, old_path))

    def on_created(self, event):
        self._emit("created", event.src_path, event.is_directory)

    def on_modified(self, event):
        self._emit("modified", event.src_path, event.is_directory)

    def on_deleted(self, event):
        self._emit("deleted", event.src_path, event.is_directory)

    def on_moved(self, event):
        self._emit("moved", event.dest_path, event.is_directory, event.src_path)


class _PollingMonitor:
    def __init__(self, includes: list[str], excludes: list[str], callback):
        self.includes = includes
        self.excludes = excludes
        self.callback = callback
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="FileSentryPolling", daemon=True)
        self.previous: dict[str, tuple[int, int]] = {}

    def _in_scope(self, path: Path) -> bool:
        text = os.path.normcase(str(path))
        return any(text == os.path.normcase(root) or text.startswith(os.path.normcase(root) + os.sep) for root in self.includes) and not any(
            text == os.path.normcase(root) or text.startswith(os.path.normcase(root) + os.sep) for root in self.excludes
        )

    def _snapshot(self) -> dict[str, tuple[int, int]]:
        current: dict[str, tuple[int, int]] = {}
        for root in self.includes:
            root_path = Path(root)
            if not root_path.exists():
                continue
            try:
                for path in root_path.rglob("*"):
                    if not path.is_file() or not self._in_scope(path):
                        continue
                    try:
                        stat = path.stat()
                        current[str(path)] = (stat.st_mtime_ns, stat.st_size)
                    except OSError:
                        continue
            except OSError:
                continue
        return current

    def _run(self) -> None:
        self.previous = self._snapshot()
        while not self.stop_event.wait(1.0):
            current = self._snapshot()
            old_paths, new_paths = set(self.previous), set(current)
            for path in sorted(new_paths - old_paths):
                self.callback(make_event("created", path))
            for path in sorted(old_paths - new_paths):
                self.callback(make_event("deleted", path))
            for path in sorted(old_paths & new_paths):
                if self.previous[path] != current[path]:
                    self.callback(make_event("modified", path))
            self.previous = current

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=3)


class MonitorManager:
    def __init__(self, callback, in_scope):
        self.callback = callback
        self.in_scope = in_scope
        self.observer = None
        self.polling = None

    def start(self, includes: list[str], excludes: list[str]) -> None:
        self.stop()
        if not includes:
            return
        if Observer and FileSystemEventHandler:
            self.observer = Observer()
            handler = _WatchdogHandler(self.callback, self.in_scope)
            for root in includes:
                if Path(root).exists():
                    self.observer.schedule(handler, root, recursive=True)
            self.observer.start()
        else:
            self.polling = _PollingMonitor(includes, excludes, self.callback)
            self.polling.start()

    def stop(self) -> None:
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
            self.observer = None
        if self.polling:
            self.polling.stop()
            self.polling = None
