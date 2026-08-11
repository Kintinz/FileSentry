"""Passive local network telemetry for FileSentry V1.

The monitor never performs DNS lookups, port scans, uploads or connection
blocking.  It reads the operating system's current socket table through
psutil, keeps a short in-memory snapshot and emits explainable indicators.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
from typing import Callable

try:
    import psutil
except ImportError:  # pragma: no cover - exercised when optional dependency is absent
    psutil = None


SUSPICIOUS_REMOTE_PORTS = {4444, 5555, 6666, 6667, 1337, 31337, 3389, 5900, 6660}
COMMON_SERVICE_PORTS = {53, 80, 123, 443, 465, 587, 853, 993, 995, 5222, 5228}
COMMON_LISTEN_PORTS = {53, 80, 123, 135, 139, 443, 445, 3389, 5353, 5985, 5986}
PUBLICLY_REACHABLE_ADMIN_PORTS = {22, 23, 3389, 5900, 5985, 5986}
WRITABLE_SEGMENTS = {
    os.path.normcase(os.environ.get("TEMP", "")),
    os.path.normcase(os.environ.get("TMP", "")),
    os.path.normcase(os.environ.get("LOCALAPPDATA", "")),
    os.path.normcase(os.environ.get("APPDATA", "")),
    os.path.normcase(os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")),
    os.path.normcase(os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")),
}


def _address(value) -> tuple[str, int] | None:
    if not value:
        return None
    try:
        return str(value.ip if hasattr(value, "ip") else value[0]), int(value.port if hasattr(value, "port") else value[1])
    except (AttributeError, IndexError, TypeError, ValueError):
        return None


def _is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
        return not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_unspecified
            or parsed.is_reserved
        )
    except ValueError:
        return False


def _is_writable_process(path: str | None) -> bool:
    if not path:
        return False
    normalized = os.path.normcase(os.path.abspath(path))
    return any(segment and (normalized == segment or normalized.startswith(segment + os.sep)) for segment in WRITABLE_SEGMENTS)


def _process_details(pid: int | None) -> tuple[str, str]:
    if not pid or psutil is None:
        return "unknown", ""
    try:
        process = psutil.Process(pid)
        name = process.name() or "unknown"
        try:
            executable = process.exe() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            executable = ""
        return name, executable
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return "unknown", ""


def _risk_indicators(connection: dict) -> list[dict[str, str]]:
    risks: list[dict[str, str]] = []
    remote_port = connection.get("remote_port")
    local_port = connection.get("local_port")
    if connection.get("direction") == "inbound_listener" and connection.get("wildcard_local") and local_port not in COMMON_LISTEN_PORTS:
        risks.append({"code": "unexpected_listener", "title": "Cổng đang lắng nghe trên mọi giao diện", "severity": "warning"})
    if connection.get("direction") == "inbound_established" and connection.get("is_external") and local_port in PUBLICLY_REACHABLE_ADMIN_PORTS:
        risks.append({"code": "public_admin_service", "title": "Kết nối Internet tới cổng quản trị", "severity": "critical"})
    if connection.get("is_external") and remote_port in SUSPICIOUS_REMOTE_PORTS:
        risks.append({"code": "suspicious_remote_port", "title": "Kết nối ra cổng thường cần kiểm tra", "severity": "warning"})
    if connection.get("is_external") and _is_writable_process(connection.get("process_path")):
        risks.append({"code": "writable_process_network", "title": "Tiến trình từ thư mục người dùng đang kết nối Internet", "severity": "warning"})
    if connection.get("is_external") and remote_port not in COMMON_SERVICE_PORTS and connection.get("status") == "ESTABLISHED":
        risks.append({"code": "uncommon_remote_port", "title": "Kết nối ra cổng dịch vụ không phổ biến", "severity": "info"})
    return risks


class NetworkMonitor:
    """Poll the local socket table and emit only new/interesting connections."""

    def __init__(self, callback: Callable[[dict], None], interval: float = 5.0):
        self.callback = callback
        self.interval = max(2.0, float(interval))
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self._known: set[str] = set()
        self._connections: list[dict] = []
        self._last_scan = None
        self._last_error = None
        self._last_external_count = 0
        self._baseline_ready = False
        self._last_emitted: dict[str, float] = {}

    @property
    def backend(self) -> str:
        return "psutil" if psutil is not None else "unavailable"

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="FileSentryNetwork", daemon=True)
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

    def _read_connections(self) -> list[dict]:
        if psutil is None:
            return []
        rows: list[dict] = []
        try:
            raw_connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            raise RuntimeError("Không đủ quyền đọc bảng kết nối mạng cục bộ.") from exc
        for raw in raw_connections:
            local = _address(raw.laddr)
            remote = _address(raw.raddr)
            if not local:
                continue
            process_name, process_path = _process_details(raw.pid)
            remote_address = remote[0] if remote else ""
            row = {
                "protocol": "TCP" if raw.type == 1 else "UDP",
                "local_address": local[0],
                "local_port": local[1],
                "remote_address": remote_address,
                "remote_port": remote[1] if remote else None,
                "status": str(raw.status or ""),
                "pid": int(raw.pid) if raw.pid else None,
                "process_name": process_name,
                "process_path": process_path,
                "direction": (
                    "inbound_listener" if str(raw.status or "") == "LISTEN"
                    else "inbound_established" if str(raw.status or "") == "ESTABLISHED" and local[1] in COMMON_LISTEN_PORTS
                    else "outbound_or_udp"
                ),
                "wildcard_local": local[0] in {"0.0.0.0", "::", ""},
                "is_external": bool(remote_address and _is_public(remote_address)),
            }
            row["risk"] = _risk_indicators(row)
            rows.append(row)
        return sorted(rows, key=lambda item: (item["process_name"], item["remote_address"], item["remote_port"] or 0))

    @staticmethod
    def _key(row: dict) -> str:
        return "|".join(str(row.get(key, "")) for key in ("protocol", "local_address", "local_port", "remote_address", "remote_port", "status", "pid"))

    def scan_once(self) -> list[dict]:
        try:
            rows = self._read_connections()
            error = None
        except RuntimeError as exc:
            rows = []
            error = str(exc)
        now = time.time()
        current_keys = {self._key(row) for row in rows}
        new_rows = [row for row in rows if self._key(row) not in self._known]
        with self.lock:
            self._connections = rows[-200:]
            self._last_scan = now
            self._last_error = error
            self._last_external_count = sum(1 for row in rows if row.get("is_external"))
            baseline_ready = self._baseline_ready
            self._known = current_keys
            self._baseline_ready = True

        if baseline_ready:
            for row in new_rows:
                row_key = self._key(row)
                previous_emit = self._last_emitted.get(row_key, 0.0)
                if now - previous_emit < 60:
                    continue
                if not row.get("is_external") and not row.get("risk"):
                    continue
                self._last_emitted[row_key] = now
                self.callback({
                    "event_type": "network_connection",
                    "path": f"network://{row['protocol'].lower()}/{row['remote_address'] or row['local_address']}:{row['remote_port'] or row['local_port']}",
                    "source": "network_monitor",
                    "details": row,
                    "risks": row.get("risk", []),
                })
            self._last_emitted = {
                key: timestamp for key, timestamp in self._last_emitted.items() if now - timestamp < 300
            }
        return rows

    def snapshot(self) -> list[dict]:
        with self.lock:
            return [dict(row, risk=list(row.get("risk", []))) for row in self._connections]

    def status(self) -> dict:
        with self.lock:
            return {
                "backend": self.backend,
                "running": bool(self.thread and self.thread.is_alive()),
                "last_scan": self._last_scan,
                "last_error": self._last_error,
                "connection_count": len(self._connections),
                "external_count": self._last_external_count,
            }
