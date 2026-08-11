"""Application orchestration for the MVP."""

from __future__ import annotations

import time
from collections import deque
from pathlib import Path
from threading import Lock

from .auth import AuthManager
from .auth_session import AuthSession
from .access_gateway import AccessGateway
from .camera_mic_guard import CameraMicGuard
from .db import Database
from .file_signals import analyze_file
from .event_correlation import correlate_double_extortion
from .folder_lock import FolderLockError, FolderLockManager
from .monitor import MonitorManager
from .network_monitor import NetworkMonitor
from .persistence_monitor import PersistenceMonitor
from .media_guard import MediaGuardError, WindowsPrivacyAdapter, normalize_origin
from .media_library import MediaLibraryError, MediaLibraryManager, MediaLibraryWatcher, default_media_excludes, discover_filesystem_roots
from .media_protection import MediaFileProtection, MediaProtectionError
from .uninstall import UninstallManager
from .paths import DATA_DIR, ensure_layout
from .secure_storage import AppCrypto
from .quarantine import QuarantineManager
from .settings import SettingsStore
from .vault import VaultManager
from .system_health import SystemHealthMonitor
from .versioning import VersionStore
from .elevation import is_admin


class FileSentryController:
    def __init__(self, data_root: Path | None = None, dpapi_scope: str = "user"):
        self.data_root = Path(data_root or DATA_DIR)
        ensure_layout(self.data_root)
        app_crypto = AppCrypto(self.data_root, dpapi_scope=dpapi_scope)
        auth_file = self.data_root / "auth.json"
        settings_file = self.data_root / "settings.json"
        version_file = self.data_root / "version.json"
        db_file = self.data_root / "filesentry.db"
        self.auth = AuthManager(auth_file, crypto=app_crypto)
        self.auth_session = AuthSession()
        self.settings = SettingsStore(settings_file, crypto=app_crypto, data_dir=self.data_root)
        self.version = VersionStore(version_file, app_crypto)
        self.db = Database(db_file, crypto=app_crypto, chain_path=self.data_root / "logs" / "intrusion_chain.log")
        self.folder_lock = FolderLockManager(self.data_root, crypto=app_crypto)
        self.quarantine = QuarantineManager(app_crypto, self.data_root)
        self.media = WindowsPrivacyAdapter()
        self.media_library = MediaLibraryManager(self.data_root, crypto=app_crypto)
        self.media_library_watcher = MediaLibraryWatcher(self._handle_media_library_event)
        self.media_file_protection = MediaFileProtection()
        self.access_gateway = AccessGateway()
        self.vault = VaultManager(crypto=app_crypto, root=self.data_root, access_gateway=self.access_gateway)
        self.monitor = MonitorManager(self._handle_event, self.settings.in_scope)
        self.network = NetworkMonitor(self._handle_network_event)
        self.persistence = PersistenceMonitor(self._handle_persistence_event)
        self.health = SystemHealthMonitor(self._handle_health_event)
        self.media_watcher = CameraMicGuard(self.media, self.access_gateway, self._media_is_managed, self._handle_media_guard_event)
        self.recent_actions = deque()
        self.last_ransomware_alert = 0.0
        self.last_double_extension_alert: dict[str, float] = {}
        self.last_file_signal_alert: dict[tuple[str, str], float] = {}
        self.recent_file_events = deque(maxlen=800)
        self.recent_network_events = deque(maxlen=300)
        self.last_double_extortion_alert: dict[str, float] = {}
        self.last_double_extortion_correlation: dict | None = None
        self.double_extortion_count = 0
        self.lock = Lock()
        self.callbacks = []
        self._folder_lock_startup_findings = self.folder_lock.verify_lock_integrity()
        for finding in self._folder_lock_startup_findings:
            self.db.record_audit("folder_lock_integrity_mismatch", {"severity": "critical", **finding})
        self.start_monitor()
        self.network.start()
        self.persistence.start()
        self.health.start()
        self.media_watcher.start()

    def subscribe(self, callback) -> None:
        self.callbacks.append(callback)

    def notify(self) -> None:
        for callback in list(self.callbacks):
            try:
                callback()
            except Exception:
                continue

    def start_monitor(self) -> None:
        if self.settings.is_active():
            includes, excludes = self.settings.effective_paths()
            self.monitor.start(includes, excludes)
        else:
            self.monitor.stop()

    def stop(self) -> None:
        self.monitor.stop()
        self.network.stop()
        self.persistence.stop()
        self.health.stop()
        self.media_watcher.stop()
        self.media_library_watcher.stop()

    def network_state(self) -> dict:
        return {**self.network.status(), "connections": self.network.snapshot()}

    def correlation_state(self) -> dict:
        latest = dict(self.last_double_extortion_correlation or {})
        detected_at = float(latest.get("detected_at", 0.0) or 0.0)
        window = float(self.settings.data.get("double_extortion_window_seconds", 120))
        latest["active"] = bool(detected_at and time.time() - detected_at <= window)
        return {
            "active": latest["active"],
            "count": self.double_extortion_count,
            "latest": latest,
            "window_seconds": window,
        }

    def persistence_state(self) -> dict:
        return {**self.persistence.status(), "entries": self.persistence.snapshot()}

    def health_state(self) -> dict:
        return self.health.state()

    def access_state(self, resource: str) -> dict:
        return self.access_gateway.status(resource)

    def access_snapshot(self) -> list[dict]:
        return self.access_gateway.snapshot()

    def folder_lock_state(self) -> dict:
        return {
            "locks": self.folder_lock.list_locks(),
            "integrity_findings": self.folder_lock.verify_lock_integrity(),
        }

    def verify_folder_lock_integrity(self, username: str = "system") -> dict:
        findings = self.folder_lock.verify_lock_integrity()
        for finding in findings:
            self.db.record_audit("folder_lock_integrity_mismatch", {"username": username, "severity": "critical", **finding})
        return {"ok": not findings, "findings": findings}

    def lock_folder(self, path: str, username: str = "admin") -> dict:
        item = self.folder_lock.lock_folder(path)
        self.db.record_audit("folder_locked", {"lock_id": item["id"], "path": item["original_path"], "owner_sid": item["owner_sid"], "username": username})
        self.notify()
        return item

    def unlock_folder(self, lock_id: str, username: str = "admin") -> dict:
        item = self.folder_lock.unlock_folder(lock_id)
        self.db.record_audit("folder_unlocked", {"lock_id": item["id"], "path": item["original_path"], "username": username})
        self.notify()
        return item

    def prepare_uninstall(self, username: str = "admin") -> dict:
        manager = UninstallManager(self.data_root)
        return manager.release_folder_locks(
            self.folder_lock,
            audit_callback=lambda action, details: self.db.record_audit(
                action, {**details, "username": username}
            ),
        )

    def emergency_unlock_all_folders(self, username: str = "admin") -> dict:
        if not is_admin():
            raise FolderLockError("Mở khóa khẩn cấp yêu cầu FileSentry đang chạy với quyền Administrator.")
        try:
            result = self.folder_lock.unlock_all_for_uninstall()
        except FolderLockError as exc:
            self.db.record_audit("folder_lock_emergency_unlock_failed", {"error": str(exc), "username": username})
            raise
        self.db.record_audit("folder_lock_emergency_unlock_all", {"count": len(result.get("unlocked", [])), "username": username})
        self.notify()
        return result

    def media_library_state(self) -> dict:
        items = self.media_library.list_items()
        counts = {"image": 0, "video": 0, "audio": 0, "private_vault": 0, "delete_protected": 0, "missing": 0}
        for item in items:
            media_type = item.get("media_type")
            if media_type in counts and item.get("present", item.get("exists", False)):
                counts[media_type] += 1
            if item.get("storage_mode") == "private_vault":
                counts["private_vault"] += 1
            if item.get("delete_protected"):
                counts["delete_protected"] += 1
            if item.get("missing"):
                counts["missing"] += 1
        return {
            "items": items,
            "counts": counts,
            "last_scan_at": self.media_library.data.get("last_scan_at"),
            "last_scan_roots": self.media_library.data.get("last_scan_roots", []),
        }

    def scan_media_library(self, username: str = "admin", full_machine: bool = True, *, progress_callback=None, cancel_event=None) -> dict:
        if full_machine:
            includes = discover_filesystem_roots()
            excludes = default_media_excludes(self.data_root)
        else:
            includes, excludes = self.settings.effective_paths()
        result = self.media_library.scan(includes, excludes, progress_callback=progress_callback, cancel_event=cancel_event)
        if not result.get("cancelled"):
            try:
                result["watching"] = self.media_library_watcher.start(includes, excludes)
            except OSError:
                result["watching"] = False
        else:
            result["watching"] = bool(self.media_library_watcher.observer)
        self.db.record_audit("media_library_scanned", {**result, "username": username})
        self.notify()
        return {**result, **self.media_library_state()}

    def _handle_media_library_event(self, event_type: str, path: str, old_path: str | None = None) -> None:
        try:
            item = self.media_library.apply_filesystem_event(event_type, path, old_path)
        except (OSError, ValueError):
            return
        if item is None:
            return
        self.db.record_audit(
            "media_library_filesystem_event",
            {"event_type": event_type, "item_id": item.get("id"), "path": str(path), "old_path": old_path},
        )
        self.notify()

    def register_media_file(self, path: str, username: str = "admin") -> dict:
        item = self.media_library.register(path)
        self.db.record_audit("media_file_registered", {"item_id": item["id"], "media_type": item["media_type"], "username": username})
        self.notify()
        return item

    def set_media_file_policy(
        self,
        item_id: str,
        *,
        delete_protected: bool | None = None,
        export_protected: bool | None = None,
        username: str = "admin",
    ) -> dict:
        item = self.media_library.get(item_id)
        if item.get("storage_mode") == "private_vault":
            return self.media_library.set_policy(item_id, delete_protected=delete_protected, export_protected=export_protected)
        if export_protected:
            raise MediaLibraryError("Chặn gửi ra ngoài tuyệt đối cần đưa file vào Kho riêng mã hóa.")
        if delete_protected is not None:
            self.media_file_protection.set_delete_protected(item["path"], bool(delete_protected))
        updated = self.media_library.set_policy(item_id, delete_protected=delete_protected, export_protected=False)
        self.db.record_audit(
            "media_file_policy_changed",
            {"item_id": item_id, "delete_protected": updated.get("delete_protected"), "username": username},
        )
        self.notify()
        return updated

    def secure_media_file(self, item_id: str, username: str = "admin") -> dict:
        item = self.media_library.get(item_id)
        if item.get("storage_mode") == "private_vault":
            return item
        source = Path(item["path"])
        had_delete_protection = bool(item.get("delete_protected"))
        if had_delete_protection:
            try:
                self.media_file_protection.set_delete_protected(source, False)
            except MediaProtectionError as exc:
                raise MediaLibraryError(
                    "File đang khóa xóa ở mức Windows. FileSentry chưa thể tạm gỡ quyền này để đưa file vào Kho riêng. "
                    "Hãy đóng ứng dụng đang mở file và chạy bản FileSentry mới với quyền Administrator."
                ) from exc
        try:
            self.unlock_vault_session(username)
            manifest = self.vault.import_file(source, remove_source=True, export_blocked=True)
            updated = self.media_library.mark_private_vault(item_id, manifest["id"])
        except Exception:
            if had_delete_protection and source.is_file():
                try:
                    self.media_file_protection.set_delete_protected(source, True)
                except Exception:
                    pass
            raise
        self.db.record_audit("media_file_moved_to_private_vault", {"item_id": item_id, "username": username})
        self.notify()
        return updated

    def remove_media_file_policy(self, item_id: str, username: str = "admin") -> dict:
        item = self.media_library.get(item_id)
        if item.get("storage_mode") != "private_vault" and item.get("delete_protected"):
            self.media_file_protection.set_delete_protected(item["path"], False)
        updated = self.media_library.remove_policy(item_id)
        self.db.record_audit("media_file_policy_removed", {"item_id": item_id, "username": username})
        self.notify()
        return updated

    def clear_media_library_inventory(self, username: str = "admin") -> dict:
        result = self.media_library.clear_external_inventory(
            remove_delete_protection=lambda path: self.media_file_protection.set_delete_protected(path, False)
        )
        self.db.record_audit(
            "media_library_inventory_cleared",
            {
                "cleared": len(result.get("cleared", [])),
                "skipped_private_vault": len(result.get("skipped_private_vault", [])),
                "failures": result.get("failures", []),
                "username": username,
            },
        )
        self.notify()
        return {**result, **self.media_library_state()}

    def open_media_item(self, item_id: str, username: str = "admin") -> dict:
        item = self.media_library.get(item_id)
        if item.get("storage_mode") == "private_vault":
            self.unlock_vault_session(username)
            content = self.vault.read_bytes(item["vault_item_id"])
            self.db.record_audit("media_item_previewed_in_memory", {"item_id": item_id, "username": username})
            return {"name": item.get("name", ""), "media_type": item.get("media_type"), "storage_mode": "private_vault", "bytes": content}
        path = Path(item.get("path", ""))
        if not path.is_file():
            raise MediaLibraryError("File media không còn tồn tại trên máy.")
        self.db.record_audit("media_item_open_requested", {"item_id": item_id, "username": username})
        return {"name": item.get("name", ""), "media_type": item.get("media_type"), "storage_mode": "external", "path": str(path)}

    def unlock_vault_session(self, username: str = "admin") -> dict:
        self.access_gateway.unlock("vault")
        self.db.record_audit("vault_session_unlocked", {"username": username, "duration_minutes": self.access_gateway.default_minutes})
        self.notify()
        return self.access_gateway.status("vault")

    def _media_is_managed(self, kind: str) -> bool:
        state = self.settings.data.get("media_guard", {}).get(kind, {})
        return bool(state.get("access_managed", False) or state.get("mode") in {"locked", "temporary"})

    def _handle_media_guard_event(self, event: dict) -> None:
        details = event.get("details", {})
        self.db.record_event({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event["event_type"],
            "path": event["path"],
            "source": event.get("source", "camera_mic_guard"),
            "details": details,
        })
        # Every revert is already retained as an event. Group only the visible
        # alert stream so a thrashing camera/microphone does not overwhelm the
        # operator while preserving the forensic timeline.
        if event["event_type"] == "unauthorized_media_access_reverted" and not details.get("alert_recommended", True):
            self.notify()
            return
        severity = "critical" if event["event_type"] == "unauthorized_media_access_reverted" else "warning"
        self.db.record_alert(
            severity,
            "Camera/Microphone Guard phát hiện thay đổi ngoài FileSentry",
            f"Đã xử lý tài nguyên {details.get('device', 'media')}: {details.get('action', details.get('error', 'unknown'))}.",
            event["path"],
        )
        self.notify()

    def _prune_correlation_buffers(self, now: float) -> None:
        window = float(self.settings.data.get("double_extortion_window_seconds", 120))
        while self.recent_file_events and now - float(self.recent_file_events[0].get("_observed_at", 0.0)) > window:
            self.recent_file_events.popleft()
        while self.recent_network_events and now - float(self.recent_network_events[0].get("_observed_at", 0.0)) > window:
            self.recent_network_events.popleft()

    def _evaluate_double_extortion(self, now: float, trigger_path: str) -> None:
        settings = self.settings.data
        correlation = correlate_double_extortion(
            list(self.recent_file_events),
            list(self.recent_network_events),
            now,
            window_seconds=float(settings.get("double_extortion_window_seconds", 120)),
            min_destructive_events=int(settings.get("double_extortion_file_min_events", 5)),
            ransomware_threshold=int(settings.get("ransomware_threshold", 20)),
        )
        if not correlation:
            return
        fingerprint = str(correlation.get("fingerprint", ""))
        previous = self.last_double_extortion_alert.get(fingerprint, 0.0)
        if now - previous <= float(correlation.get("window_seconds", 120)):
            return
        self.last_double_extortion_alert[fingerprint] = now
        correlation["detected_at"] = now
        correlation["trigger_path"] = trigger_path
        self.last_double_extortion_correlation = dict(correlation)
        self.double_extortion_count += 1
        self.db.record_event({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "event_type": "double_extortion_correlation",
            "path": str(correlation.get("path") or trigger_path),
            "source": "event_correlation",
            "details": correlation,
        })
        self.db.record_alert(
            correlation["severity"],
            correlation["title"],
            correlation["message"],
            str(correlation.get("path") or trigger_path),
        )

    def _handle_network_event(self, event: dict) -> None:
        now = time.time()
        observed = dict(event)
        observed["_observed_at"] = now
        self.recent_network_events.append(observed)
        self._prune_correlation_buffers(now)
        self.db.record_event({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "event_type": event["event_type"],
            "path": event["path"],
            "source": event.get("source", "network_monitor"),
            "details": event.get("details", {}),
        })
        risks = event.get("risks", [])
        if risks:
            critical_codes = {"unexpected_listener", "public_admin_service"}
            severity = "critical" if any(item.get("code") in critical_codes for item in risks) else "warning"
            titles = ", ".join(item.get("title", "Network indicator") for item in risks)
            self.db.record_alert(
                severity,
                "Chỉ báo kết nối mạng cần kiểm tra",
                f"{titles}. FileSentry chỉ phát hiện chỉ báo, chưa kết luận có xâm nhập.",
                event["path"],
            )
        self._evaluate_double_extortion(now, event["path"])
        self.notify()

    def _handle_persistence_event(self, event: dict) -> None:
        self.db.record_event({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event["event_type"],
            "path": event["path"],
            "source": event.get("source", "persistence_monitor"),
            "details": event.get("details", {}),
        })
        risks = event.get("risks", [])
        if risks:
            self.db.record_alert(
                "warning",
                "Persistence mới cần kiểm tra",
                ", ".join(item.get("title", "Persistence indicator") for item in risks),
                event["path"],
            )
        self.notify()

    def _handle_health_event(self, event: dict) -> None:
        self.db.record_event({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event["event_type"],
            "path": event["path"],
            "source": event.get("source", "system_health"),
            "details": event.get("details", {}),
        })
        self.db.record_alert(
            "critical" if event.get("details", {}).get("status") == "warning" else "warning",
            "Trạng thái Antivirus/EDR cần kiểm tra",
            f"Trạng thái hiện tại: {event.get('details', {}).get('status', 'unknown')}.",
            event["path"],
        )
        self.notify()

    def set_protection(self, enabled: bool, username: str = "admin") -> None:
        self.settings.save({"enabled": enabled, "pause_until": None})
        self.db.record_audit("protection_enabled" if enabled else "protection_disabled", {"username": username})
        self.start_monitor()
        self.notify()

    def pause(self, minutes: int, username: str = "admin") -> None:
        until = time.time() + max(1, minutes) * 60
        self.settings.save({"pause_until": until})
        self.db.record_audit("protection_paused", {"minutes": minutes, "username": username})
        self.monitor.stop()
        self.notify()

    def lock_protected_access(self, minutes: int | None = None, username: str = "admin") -> None:
        lock_until = time.time() + minutes * 60 if minutes else None
        self.settings.save({"protected_access_locked": True, "protected_access_lock_until": lock_until})
        self.db.record_audit("protected_access_locked", {"minutes": minutes, "username": username})
        self.notify()

    def unlock_protected_access(self, username: str = "admin") -> None:
        self.settings.save({"protected_access_locked": False, "protected_access_lock_until": None})
        self.db.record_audit("protected_access_unlocked", {"username": username})
        self.notify()

    def add_path(self, kind: str, path: str, username: str = "admin") -> None:
        self.settings.add_path(kind, path)
        self.db.record_audit("scope_added", {"kind": kind, "path": path, "username": username})
        self.start_monitor()
        self.notify()

    def protected_storage_state(self) -> dict:
        return {"areas": list(self.settings.data.get("storage_areas", []))}

    def create_protected_storage(self, parent: str, name: str = "FileSentry Protected Storage", username: str = "admin") -> dict:
        existing_ids = {area.get("id") for area in self.settings.data.get("storage_areas", [])}
        area = self.settings.create_storage_area(parent, name)
        try:
            self.settings.add_path("include", area["path"])
        except Exception:
            if area.get("id") not in existing_ids:
                self.settings.remove_storage_area(area["id"])
            raise
        self.db.record_audit(
            "protected_storage_created",
            {"path": area["path"], "name": area["name"], "username": username},
        )
        self.start_monitor()
        self.notify()
        return area

    def remove_protected_storage(self, area_id: str, username: str = "admin") -> dict:
        area = self.settings.remove_storage_area(area_id)
        self.db.record_audit(
            "protected_storage_management_removed",
            {"path": area["path"], "username": username, "folder_retained": True},
        )
        self.notify()
        return area

    def remove_path(self, kind: str, path: str, username: str = "admin") -> None:
        self.settings.remove_path(kind, path)
        self.db.record_audit("scope_removed", {"kind": kind, "path": path, "username": username})
        self.start_monitor()
        self.notify()

    def media_state(self, kind: str) -> dict:
        state = self.settings.data["media_guard"][kind]
        if state.get("locked_until") and float(state["locked_until"]) <= time.time():
            # A timed deny expires into the safer locked state. A new unlock
            # session must be explicitly authenticated by the user.
            self.set_media_mode(kind, "locked", username="system-expiry")
            state = self.settings.data["media_guard"][kind]
        policy = self.media.read_policy(kind)
        return {
            **state,
            "policy": policy,
            "system_deny": self.media.is_force_denied(policy),
            "unlock_session": self.access_gateway.status(kind),
        }

    def set_media_mode(self, kind: str, mode: str, minutes: int | None = None, username: str = "admin") -> None:
        if mode not in {"locked", "temporary" , "unlocked"}:
            raise MediaGuardError("Chế độ Media Guard không hợp lệ.")
        all_media = self.settings.data["media_guard"]
        state = dict(all_media[kind])
        if mode in {"locked", "temporary"}:
            if state.get("previous_policy") is None:
                state["previous_policy"] = self.media.apply_force_deny(kind)
            else:
                self.media.apply_force_deny(kind)
            self.access_gateway.lock(kind)
            state["mode"] = mode
            state["access_managed"] = True
            state["locked_until"] = time.time() + minutes * 60 if mode == "temporary" and minutes else None
            action = "media_temporary_locked" if mode == "temporary" else "media_locked"
        else:
            issued_session = username != "system-expiry"
            if issued_session:
                self.access_gateway.unlock(kind)
            else:
                self.access_gateway.lock(kind)
            try:
                self.media.restore_policy(kind, state.get("previous_policy"))
            except Exception:
                self.access_gateway.lock(kind)
                raise
            state["mode"] = "unlocked"
            state["locked_until"] = None
            state["previous_policy"] = None
            state["access_managed"] = True
            action = "media_unlocked"
        all_media[kind] = state
        self.settings.save({"media_guard": all_media})
        self.db.record_audit(action, {"device": kind, "username": username, "mode": mode})
        self.notify()

    def add_media_site(self, kind: str, origin: str, username: str = "admin") -> str:
        normalized = normalize_origin(origin)
        all_media = self.settings.data["media_guard"]
        sites = list(all_media[kind].get("allowed_sites", []))
        if normalized not in sites:
            sites.append(normalized)
            all_media[kind]["allowed_sites"] = sorted(sites)
            self.settings.save({"media_guard": all_media})
            self.db.record_audit("media_site_added", {"device": kind, "origin": normalized, "username": username})
        return normalized

    def remove_media_site(self, kind: str, origin: str, username: str = "admin") -> None:
        normalized = normalize_origin(origin)
        all_media = self.settings.data["media_guard"]
        all_media[kind]["allowed_sites"] = [site for site in all_media[kind].get("allowed_sites", []) if site != normalized]
        self.settings.save({"media_guard": all_media})
        self.db.record_audit("media_site_removed", {"device": kind, "origin": normalized, "username": username})

    def _is_double_extension(self, path: str) -> bool:
        suffixes = [suffix.lower() for suffix in Path(path).suffixes]
        executable = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta"}
        document = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".jpg", ".png"}
        return len(suffixes) >= 2 and suffixes[-1] in executable and suffixes[-2] in document

    def _handle_event(self, event: dict) -> None:
        if not self.settings.is_active() or not self.settings.in_scope(event["path"]):
            return
        if event.get("is_dir"):
            return
        self.db.record_event(event)
        now = time.time()
        path = str(event["path"])
        double_extension = self._is_double_extension(path)
        observed = dict(event)
        observed["path"] = path
        observed["double_extension"] = double_extension
        observed["_observed_at"] = now
        self.recent_file_events.append(observed)
        self._prune_correlation_buffers(now)
        self.recent_actions.append((now, event["event_type"], path))
        window = float(self.settings.data.get("ransomware_window_seconds", 5))
        while self.recent_actions and self.recent_actions[0][0] < now - window:
            self.recent_actions.popleft()
        threshold = int(self.settings.data.get("ransomware_threshold", 20))
        destructive = sum(1 for _, kind, _ in self.recent_actions if kind in {"deleted", "moved", "created"})
        if destructive >= threshold and now - self.last_ransomware_alert > 30:
            self.last_ransomware_alert = now
            self.db.record_alert(
                "critical",
                "Hành vi file bất thường",
                f"Đã phát hiện {destructive} thay đổi file trong {window:.0f} giây.",
                path,
            )
        last_alert = self.last_double_extension_alert.get(path, 0.0)
        if double_extension and now - last_alert > 60:
            self.last_double_extension_alert[path] = now
            self.db.record_alert(
                "warning",
                "File có đuôi kép đáng chú ý",
                "Tên file có dạng tài liệu + phần mở rộng thực thi.",
                path,
            )
        for signal in analyze_file(path):
            signal_key = (path, signal["code"])
            previous = self.last_file_signal_alert.get(signal_key, 0.0)
            if now - previous <= 60:
                continue
            self.last_file_signal_alert[signal_key] = now
            self.db.record_alert(
                signal["severity"],
                signal["title"],
                "Đây là chỉ báo hành vi; FileSentry không kết luận file chắc chắn là mã độc.",
                path,
            )
        self._evaluate_double_extortion(now, path)
        self.notify()

    def status(self) -> dict:
        data = self.settings.data
        had_pause = bool(data.get("pause_until"))
        active = self.settings.is_active()
        if had_pause and not self.settings.data.get("pause_until") and data.get("enabled"):
            self.start_monitor()
            active = True
        access_locked = bool(data.get("protected_access_locked"))
        lock_until = data.get("protected_access_lock_until")
        if access_locked and lock_until and float(lock_until) <= time.time():
            self.settings.save({"protected_access_locked": False, "protected_access_lock_until": None})
            access_locked = False
            lock_until = None
        paused = bool(data.get("pause_until") and float(data["pause_until"]) > time.time())
        if paused:
            label, color = "TẠM DỪNG", "#F59E0B"
        elif not data.get("enabled"):
            label, color = "ĐÃ TẮT", "#EF4444"
        elif not data.get("include_paths"):
            label, color = "CHƯA CẤU HÌNH", "#F59E0B"
        elif active:
            label, color = "ĐANG BẢO VỆ", "#22C55E"
        else:
            label, color = "ĐÃ TẮT", "#EF4444"
        return {
            "active": active,
            "label": label,
            "color": color,
            "access_locked": access_locked,
            "version": self.version.data,
            "settings": self.settings.data,
        }
