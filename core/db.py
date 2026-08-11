"""SQLite persistence for events, alerts and administrative audit records."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

from .secure_storage import AppCrypto
from .security import reject_symlink
from .intrusion_log import IntrusionChain


SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path, crypto: AppCrypto | None = None, chain_path: Path | None = None):
        self.path = path
        reject_symlink(self.path, "Cơ sở dữ liệu không được là symbolic link.")
        self.crypto = crypto or AppCrypto(path.parent)
        self.chain = IntrusionChain(chain_path or path.parent / "logs" / "intrusion_chain.log", self.crypto)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA secure_delete=ON")
        try:
            yield connection
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    old_path TEXT,
                    is_dir INTEGER NOT NULL DEFAULT 0,
                    size INTEGER,
                    sha256 TEXT,
                    source TEXT NOT NULL DEFAULT 'monitor',
                    details_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    path TEXT,
                    acknowledged INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT
                );
                INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', '1');
                """
            )
            self._migrate_legacy_rows(connection)

    def _migrate_legacy_rows(self, connection: sqlite3.Connection) -> None:
        columns = {
            "events": ("timestamp", "event_type", "path", "old_path", "is_dir", "size", "sha256", "source", "details_json"),
            "alerts": ("timestamp", "severity", "title", "message", "path"),
            "audit_log": ("timestamp", "action", "details_json"),
        }
        for table, fields in columns.items():
            rows = connection.execute(f"SELECT id, {', '.join(fields)} FROM {table}").fetchall()
            for row in rows:
                updates = {}
                for field in fields:
                    value = row[field]
                    if value is not None and not self.crypto.is_encrypted(str(value)):
                        purpose = "events" if table == "events" else "alerts" if table == "alerts" else "audit"
                        updates[field] = self.crypto.encrypt_text(str(value), f"{purpose}:{field}")
                if updates:
                    assignments = ", ".join(f"{field}=?" for field in updates)
                    connection.execute(
                        f"UPDATE {table} SET {assignments} WHERE id=?",
                        (*updates.values(), row["id"]),
                    )

    def record_event(self, event: dict) -> None:
        encrypted = lambda key, value: self.crypto.encrypt_text(str(value), f"events:{key}") if value is not None else None
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO events(timestamp,event_type,path,old_path,is_dir,size,sha256,source,details_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    encrypted("timestamp", event.get("timestamp", utc_now())),
                    encrypted("event_type", event["event_type"]),
                    encrypted("path", event["path"]),
                    encrypted("old_path", event.get("old_path")),
                    encrypted("is_dir", int(bool(event.get("is_dir", False)))),
                    encrypted("size", event.get("size")),
                    encrypted("sha256", event.get("sha256")),
                    encrypted("source", event.get("source", "monitor")),
                    encrypted("details_json", json.dumps(event.get("details", {}), ensure_ascii=False)),
                ),
            )
        self.chain.append("event", event)

    def record_alert(self, severity: str, title: str, message: str, path: str | None = None) -> None:
        encrypted = lambda key, value: self.crypto.encrypt_text(str(value), f"alerts:{key}") if value is not None else None
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO alerts(timestamp,severity,title,message,path) VALUES (?,?,?,?,?)",
                (encrypted("timestamp", utc_now()), encrypted("severity", severity), encrypted("title", title), encrypted("message", message), encrypted("path", path)),
            )
        self.chain.append("alert", {"severity": severity, "title": title, "message": message, "path": path})

    def record_audit(self, action: str, details: dict | None = None) -> None:
        encrypted = lambda key, value: self.crypto.encrypt_text(str(value), f"audit:{key}")
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO audit_log(timestamp,action,details_json) VALUES (?,?,?)",
                (encrypted("timestamp", utc_now()), encrypted("action", action), encrypted("details_json", json.dumps(details or {}, ensure_ascii=False))),
            )
        self.chain.append("audit", {"action": action, "details": details or {}})

    def verify_intrusion_chain(self) -> dict:
        return self.chain.verify()

    def events(self, limit: int = 100) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._decode_event(dict(row)) for row in rows]

    def alerts(self, limit: int = 50) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._decode_alert(dict(row)) for row in rows]

    def audits(self, limit: int = 200) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._decode_audit(dict(row)) for row in rows]

    def _decode_event(self, row: dict) -> dict:
        for key in ("timestamp", "event_type", "path", "old_path", "is_dir", "size", "sha256", "source", "details_json"):
            if row.get(key) is not None:
                row[key] = self.crypto.decrypt_text(row[key], f"events:{key}")
        try:
            row["is_dir"] = int(row.get("is_dir", 0))
        except (TypeError, ValueError):
            row["is_dir"] = 0
        try:
            row["size"] = int(row["size"]) if row.get("size") is not None else None
        except (TypeError, ValueError):
            row["size"] = None
        try:
            row["details_json"] = json.loads(row["details_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            pass
        return row

    def _decode_alert(self, row: dict) -> dict:
        for key in ("timestamp", "severity", "title", "message", "path"):
            if row.get(key) is not None:
                row[key] = self.crypto.decrypt_text(row[key], f"alerts:{key}")
        return row

    def _decode_audit(self, row: dict) -> dict:
        for key in ("timestamp", "action", "details_json"):
            if row.get(key) is not None:
                row[key] = self.crypto.decrypt_text(row[key], f"audit:{key}")
        try:
            row["details_json"] = json.loads(row["details_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            pass
        return row

    def stats(self) -> dict:
        with self.connect() as connection:
            events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            alerts = connection.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
        return {"events": events, "alerts": alerts}
