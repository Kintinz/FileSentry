"""Conservative correlation of file activity and network indicators.

This module never claims attribution or compromise.  It only combines two
independent local observations in a bounded time window so the operator can
review a possible double-extortion sequence: destructive file activity or
double-extension names together with an external/risky connection.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


DESTRUCTIVE_FILE_EVENTS = frozenset({"created", "deleted", "moved", "modified", "renamed"})
COMMON_REMOTE_PORTS = frozenset({53, 80, 123, 443, 993, 995})


def _observed_at(event: dict) -> float:
    try:
        return float(event.get("_observed_at", event.get("observed_at", 0.0)))
    except (TypeError, ValueError):
        return 0.0


def _network_details(event: dict) -> dict:
    details = event.get("details")
    return details if isinstance(details, dict) else {}


def _network_risks(event: dict) -> list[dict]:
    risks = event.get("risks")
    if isinstance(risks, list):
        return [item for item in risks if isinstance(item, dict)]
    details = _network_details(event)
    risks = details.get("risk", [])
    return [item for item in risks if isinstance(item, dict)] if isinstance(risks, list) else []


def _is_user_writable_process(process_path: str | None) -> bool:
    if not process_path:
        return False
    normalized = os.path.normcase(str(process_path)).replace("/", "\\")
    user_profile = os.path.normcase(os.environ.get("USERPROFILE", "")).replace("/", "\\")
    return bool(user_profile and normalized.startswith(user_profile + "\\"))


def _network_is_relevant(event: dict, *, require_risk: bool) -> bool:
    details = _network_details(event)
    if not bool(details.get("is_external")):
        return False
    risks = _network_risks(event)
    if risks:
        return True
    if _is_user_writable_process(details.get("process_path")):
        return True
    try:
        remote_port = int(details.get("remote_port")) if details.get("remote_port") else None
    except (TypeError, ValueError):
        remote_port = None
    # A large file burst can justify correlating a new external connection
    # even when the socket itself has no individual risk label.  For a single
    # double-extension file, stay conservative and require a network signal.
    return not require_risk and remote_port not in COMMON_REMOTE_PORTS


def _fingerprint(file_events: list[dict], network_events: list[dict]) -> str:
    evidence = {
        "files": sorted(str(event.get("path", "")) for event in file_events),
        "network": sorted(
            f"{_network_details(event).get('process_path', '')}|{event.get('path', '')}"
            for event in network_events
        ),
    }
    return hashlib.sha256(json.dumps(evidence, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:24]


def correlate_double_extortion(
    file_events: list[dict],
    network_events: list[dict],
    now: float,
    *,
    window_seconds: float = 120.0,
    min_destructive_events: int = 5,
    ransomware_threshold: int = 20,
) -> dict | None:
    """Return explainable correlation evidence or ``None``.

    ``file_events`` and ``network_events`` are already local observations and
    carry an internal ``_observed_at`` timestamp.  The result is intentionally
    a signal, not a verdict; normal software can generate either stream.
    """
    recent_files = [
        event for event in file_events
        if 0 <= now - _observed_at(event) <= window_seconds and event.get("path")
    ]
    recent_network = [
        event for event in network_events
        if 0 <= now - _observed_at(event) <= window_seconds and event.get("path")
    ]
    if not recent_files or not recent_network:
        return None

    destructive = [event for event in recent_files if event.get("event_type") in DESTRUCTIVE_FILE_EVENTS]
    double_extensions = [event for event in recent_files if event.get("double_extension")]
    if len(destructive) < min_destructive_events and not double_extensions:
        return None

    strong_network = [event for event in recent_network if _network_is_relevant(event, require_risk=True)]
    burst_threshold = max(min_destructive_events, min(int(ransomware_threshold), 20))
    broad_network = [event for event in recent_network if _network_is_relevant(event, require_risk=False)]
    if not strong_network and not (len(destructive) >= burst_threshold and broad_network):
        return None

    network_evidence = strong_network or broad_network
    severity = "critical" if len(destructive) >= burst_threshold and network_evidence else "warning"
    file_paths = sorted({str(event.get("path")) for event in destructive + double_extensions})
    endpoints = sorted({str(event.get("path")) for event in network_evidence})
    process_paths = sorted({str(_network_details(event).get("process_path")) for event in network_evidence if _network_details(event).get("process_path")})
    risk_titles = sorted({str(item.get("title")) for event in network_evidence for item in _network_risks(event) if item.get("title")})
    result = {
        "severity": severity,
        "title": "Tương quan file + network: nguy cơ double-extortion",
        "message": (
            f"Trong {window_seconds:.0f} giây có {len(destructive)} thay đổi file"
            f" và {len(network_evidence)} kết nối ngoài có chỉ báo liên quan."
            " Đây là tương quan cần kiểm tra, không phải kết luận máy đã bị xâm nhập."
        ),
        "window_seconds": window_seconds,
        "file_events_count": len(recent_files),
        "destructive_events_count": len(destructive),
        "double_extension_count": len(double_extensions),
        "file_paths": file_paths[:25],
        "network_events_count": len(network_evidence),
        "network_endpoints": endpoints[:25],
        "process_paths": process_paths[:10],
        "network_risk_titles": risk_titles[:20],
    }
    result["fingerprint"] = _fingerprint(destructive + double_extensions, network_evidence)
    result["path"] = file_paths[0] if file_paths else endpoints[0]
    return result

