"""Encrypted incident report export assembled from local FileSentry evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from .security import reject_symlink


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class IncidentReportBuilder:
    """Build and export a local, encrypted incident timeline.

    Reports intentionally contain observations and indicators, not a claim that
    a host was compromised.  The exported file is encrypted with the same
    application key used for local data and should be opened only by a trusted
    FileSentry instance on the same Windows user profile.
    """

    FORMAT_VERSION = 1

    def __init__(self, database, controller=None):
        self.database = database
        self.controller = controller

    def build(self, hours: int = 24, limit: int = 5000) -> dict:
        hours = max(1, min(int(hours), 24 * 30))
        generated_at = datetime.now(timezone.utc)
        cutoff = generated_at - timedelta(hours=hours)

        def recent(rows: list[dict]) -> list[dict]:
            result = []
            for row in rows:
                timestamp = _parse_timestamp(row.get("timestamp"))
                if timestamp is None or timestamp >= cutoff:
                    result.append(row)
            return result

        events = recent(self.database.events(limit))
        alerts = recent(self.database.alerts(limit))
        audits = recent(self.database.audits(limit))
        timeline = [
            {"kind": "event", **row} for row in events
        ] + [
            {"kind": "alert", **row} for row in alerts
        ] + [
            {"kind": "audit", **row} for row in audits
        ]
        timeline.sort(key=lambda row: row.get("timestamp", ""))

        report = {
            "report_version": self.FORMAT_VERSION,
            "generated_at": generated_at.isoformat(timespec="seconds"),
            "window": {
                "hours": hours,
                "from": cutoff.isoformat(timespec="seconds"),
                "to": generated_at.isoformat(timespec="seconds"),
            },
            "assessment": {
                "mode": "local_observation",
                "note": "Indicators require analyst validation; this report is not proof of compromise.",
            },
            "evidence": {
                "timeline": timeline,
                "events_count": len(events),
                "alerts_count": len(alerts),
                "audits_count": len(audits),
            },
            "integrity": {
                "intrusion_chain": self.database.verify_intrusion_chain(),
            },
        }
        if self.controller is not None:
            report["posture"] = {
                "protection": self.controller.status(),
                "network": self.controller.network_state(),
                "persistence": self.controller.persistence_state(),
                "antivirus": self.controller.health_state(),
            }
        return report

    def export_encrypted(self, destination: str | Path, hours: int = 24) -> dict:
        path = reject_symlink(Path(destination).expanduser(), "Không ghi báo cáo qua symbolic link.")
        if path.suffix.lower() not in {".fsreport", ".json"}:
            raise ValueError("Báo cáo FileSentry phải có đuôi .fsreport hoặc .json.")
        report = self.build(hours=hours)
        self.database.crypto.write_json(path, report)
        return {"path": str(path), "report_version": self.FORMAT_VERSION, "hours": report["window"]["hours"]}
