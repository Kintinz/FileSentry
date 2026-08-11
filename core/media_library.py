"""Encrypted inventory and policy metadata for image, video and audio files."""

from __future__ import annotations

import os
import string
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from .secure_storage import AppCrypto
from .security import reject_symlink


IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".heic", ".heif", ".svg",
}
VIDEO_EXTENSIONS = {
    ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm", ".wmv", ".flv", ".mpeg", ".mpg", ".3gp",
}
AUDIO_EXTENSIONS = {
    ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".opus", ".wma", ".aiff", ".alac",
}
MEDIA_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS | AUDIO_EXTENSIONS


class MediaLibraryError(ValueError):
    """Raised when a media inventory or policy operation is invalid."""


def media_type_for(path: str | Path) -> str | None:
    suffix = Path(path).suffix.lower()
    if suffix in IMAGE_EXTENSIONS:
        return "image"
    if suffix in VIDEO_EXTENSIONS:
        return "video"
    if suffix in AUDIO_EXTENSIONS:
        return "audio"
    return None


def normalize_media_path(path: str | Path) -> str:
    return os.path.normcase(str(Path(path).expanduser().resolve(strict=False)))


def _is_under(path: str, roots: list[str]) -> bool:
    return any(path == root or path.startswith(root + os.sep) for root in roots)


def discover_filesystem_roots() -> list[str]:
    """Return mounted local filesystem roots that are safe to inspect."""
    roots: list[str] = []
    try:
        import psutil

        for partition in psutil.disk_partitions(all=False):
            options = str(getattr(partition, "opts", "")).lower()
            if "remote" in options:
                continue
            mountpoint = Path(str(partition.mountpoint))
            if mountpoint.is_dir():
                roots.append(normalize_media_path(mountpoint))
    except (ImportError, OSError, ValueError):
        for letter in string.ascii_uppercase:
            mountpoint = Path(f"{letter}:\\")
            if mountpoint.is_dir():
                roots.append(normalize_media_path(mountpoint))
    return sorted(set(roots))


def default_media_excludes(data_root: Path) -> list[str]:
    """Exclude OS/app/cache locations while retaining user and removable media."""
    candidates = [
        Path(data_root),
        Path(os.environ.get("SystemRoot", r"C:\Windows")),
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("ProgramData", r"C:\ProgramData")),
    ]
    for root in discover_filesystem_roots():
        drive = Path(root)
        candidates.extend((drive / "$Recycle.Bin", drive / "System Volume Information"))
    for variable in ("TEMP", "TMP"):
        value = os.environ.get(variable)
        if value:
            candidates.append(Path(value))
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Temp")
    return sorted({normalize_media_path(path) for path in candidates})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class MediaLibraryManager:
    """Keep media inventory and policy data encrypted at rest.

    The inventory never stores media bytes.  A normal item references an
    external file and can receive a Windows delete-deny policy.  An item in
    ``private_vault`` has its original bytes moved into the encrypted Vault;
    only FileSentry can then restore it through an authenticated action.
    """

    FORMAT_VERSION = 1
    MAX_SCAN_ITEMS = 20_000

    def __init__(self, root: Path, crypto: AppCrypto | None = None):
        self.root = Path(root)
        self.path = self.root / "media_library.json"
        self.crypto = crypto or AppCrypto(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._data = self._load()

    def _load(self) -> dict:
        default = {"format_version": self.FORMAT_VERSION, "items": []}
        if not self.path.exists():
            self.crypto.write_json(self.path, default)
            return default
        try:
            saved, encrypted = self.crypto.read_json(self.path)
        except (OSError, ValueError):
            saved, encrypted = {}, True
        data = deepcopy(default)
        data.update(saved if isinstance(saved, dict) else {})
        data["items"] = [item for item in data.get("items", []) if isinstance(item, dict)]
        if not encrypted:
            self.crypto.write_json(self.path, data)
        return data

    def _save(self) -> None:
        self._data["format_version"] = self.FORMAT_VERSION
        self._data["updated_at"] = _now()
        self.crypto.write_json(self.path, self._data)

    @property
    def data(self) -> dict:
        return deepcopy(self._data)

    def list_items(self) -> list[dict]:
        items = []
        for item in self._data.get("items", []):
            current = dict(item)
            present = bool(current.get("storage_mode") == "private_vault" or Path(current.get("path", "")).is_file())
            current["present"] = present
            current["exists"] = present
            current["missing"] = False if current.get("storage_mode") == "private_vault" else not present
            current["state"] = "private_vault" if current.get("storage_mode") == "private_vault" else ("active" if present else "missing")
            items.append(current)
        return sorted(items, key=lambda item: item.get("updated_at", item.get("created_at", "")), reverse=True)

    def get(self, item_id: str) -> dict:
        if not isinstance(item_id, str) or not item_id or any(character not in "0123456789abcdef-" for character in item_id.lower()):
            raise MediaLibraryError("Mục media không hợp lệ.")
        for item in self._data["items"]:
            if item.get("id") == item_id:
                return dict(item)
        raise MediaLibraryError("Không tìm thấy mục media.")

    def _find_external_by_path(self, normalized: str) -> dict | None:
        for item in self._data["items"]:
            if item.get("storage_mode") != "external":
                continue
            if normalize_media_path(item.get("path", "")) == normalized:
                return item
        return None

    def register(self, path: str | Path, *, persist: bool = True) -> dict:
        with self._lock:
            return self._register(path, persist=persist)

    def _register(self, path: str | Path, *, persist: bool = True) -> dict:
        candidate = reject_symlink(Path(path).expanduser())
        if not candidate.is_file():
            raise MediaLibraryError("Chỉ có thể quản lý một file media.")
        media_type = media_type_for(candidate)
        if media_type is None:
            raise MediaLibraryError("Định dạng này chưa được hỗ trợ trong Media Library.")
        normalized = normalize_media_path(candidate)
        stat = candidate.stat()
        existing = self._find_external_by_path(normalized)
        if existing is not None:
            existing.update({
                "name": candidate.name,
                "size": stat.st_size,
                "modified_at": stat.st_mtime,
                "present": True,
                "missing": False,
                "last_seen_at": _now(),
                "updated_at": _now(),
            })
            if persist:
                self._save()
            return dict(existing)
        item = {
            "id": uuid.uuid4().hex,
            "path": normalized,
            "name": candidate.name,
            "media_type": media_type,
            "extension": candidate.suffix.lower(),
            "size": stat.st_size,
            "modified_at": stat.st_mtime,
            "delete_protected": False,
            "export_protected": False,
            "storage_mode": "external",
            "vault_item_id": None,
            "present": True,
            "missing": False,
            "last_seen_at": _now(),
            "created_at": _now(),
            "updated_at": _now(),
        }
        self._data["items"].append(item)
        if persist:
            self._save()
        return dict(item)

    def scan(self, roots: list[str], excludes: list[str] | None = None, *, progress_callback=None, cancel_event=None) -> dict:
        with self._lock:
            return self._scan(roots, excludes, progress_callback=progress_callback, cancel_event=cancel_event)

    def _scan(self, roots: list[str], excludes: list[str] | None = None, *, progress_callback=None, cancel_event=None) -> dict:
        excluded = [normalize_media_path(path) for path in (excludes or [])]
        discovered = 0
        registered = 0
        updated = 0
        removed = 0
        scan_roots = [normalize_media_path(root) for root in roots if Path(root).is_dir()]
        scan_roots = [root for root in scan_roots if not _is_under(root, excluded)]
        limited = False
        cancelled = False
        candidates: list[Path] = []
        last_report = 0.0

        def is_cancelled() -> bool:
            return bool(cancel_event is not None and cancel_event.is_set())

        def report(phase: str, *, processed: int = 0, total: int | None = None, current: str = "", force: bool = False) -> None:
            nonlocal last_report
            if progress_callback is None:
                return
            now = time.monotonic()
            if not force and now - last_report < 0.12:
                return
            last_report = now
            percent = None
            if phase == "discovering":
                percent = int((processed / max(len(scan_roots), 1)) * 45)
            elif total:
                percent = 50 + int((processed / total) * 50)
            elif phase == "complete":
                percent = 100
            try:
                progress_callback({
                    "phase": phase,
                    "discovered": discovered,
                    "processed": processed,
                    "total": total,
                    "percent": min(percent, 100) if percent is not None else None,
                    "current": current,
                    "limited": limited,
                })
            except Exception:
                pass

        report("discovering", processed=0, force=True)
        for root in scan_roots:
            if limited or cancelled:
                break
            root_path = Path(root)
            try:
                for directory, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
                    if is_cancelled():
                        cancelled = True
                        break
                    normalized_directory = normalize_media_path(directory)
                    if _is_under(normalized_directory, excluded):
                        dirnames[:] = []
                        continue
                    dirnames[:] = [
                        name for name in dirnames
                        if not _is_under(normalize_media_path(Path(directory) / name), excluded)
                        and not os.path.islink(Path(directory) / name)
                    ]
                    for filename in filenames:
                        if is_cancelled():
                            cancelled = True
                            break
                        if len(candidates) >= self.MAX_SCAN_ITEMS:
                            limited = True
                            break
                        candidate = Path(directory) / filename
                        if candidate.is_symlink() or media_type_for(candidate) is None:
                            continue
                        try:
                            if not candidate.is_file():
                                continue
                            normalized = normalize_media_path(candidate)
                            if _is_under(normalized, excluded):
                                continue
                            candidates.append(candidate)
                            discovered = len(candidates)
                            report("discovering", processed=scan_roots.index(root) + 1, current=str(candidate))
                        except (OSError, ValueError):
                            continue
                    if limited or cancelled:
                        break
            except OSError:
                continue

        if cancelled:
            report("cancelled", processed=0, total=len(candidates), force=True)
            return {
                "scanned": discovered,
                "registered": 0,
                "updated": 0,
                "removed": 0,
                "limited": limited,
                "cancelled": True,
                "roots": scan_roots,
                "last_scan_at": self._data.get("last_scan_at"),
            }

        total = len(candidates)
        seen_paths: set[str] = set()
        processed_count = 0
        report("processing", processed=0, total=total, force=True)
        for index, candidate in enumerate(candidates, start=1):
            if is_cancelled():
                cancelled = True
                break
            try:
                normalized = normalize_media_path(candidate)
                known = self._find_external_by_path(normalized)
                before = known.copy() if known else None
                self.register(candidate, persist=False)
                current = self._find_external_by_path(normalized)
                if current is None:
                    continue
                seen_paths.add(normalized)
                if before is None:
                    registered += 1
                elif any(before.get(key) != current.get(key) for key in ("size", "modified_at", "missing", "present")):
                    updated += 1
                processed_count = index
                report("processing", processed=index, total=total, current=str(candidate))
            except (OSError, ValueError):
                continue

        if not limited and not cancelled:
            for item in self._data["items"]:
                if item.get("storage_mode") == "private_vault":
                    continue
                normalized = normalize_media_path(item.get("path", ""))
                if not _is_under(normalized, scan_roots) or _is_under(normalized, excluded) or normalized in seen_paths:
                    continue
                if not item.get("missing", False):
                    item.update({"present": False, "missing": True, "missing_at": _now(), "updated_at": _now()})
                    removed += 1

        last_scan_at = _now()
        if not cancelled:
            self._data["last_scan_at"] = last_scan_at
            self._data["last_scan_roots"] = scan_roots
            self._save()
        elif registered or updated:
            # Keep successfully processed records, but deliberately skip the
            # missing-file reconciliation because the scan was incomplete.
            self._save()
        report("cancelled" if cancelled else "complete", processed=processed_count, total=total, force=True)
        return {
            "scanned": discovered,
            "registered": registered,
            "updated": updated,
            "removed": removed,
            "limited": limited,
            "cancelled": cancelled,
            "roots": scan_roots,
            "last_scan_at": last_scan_at if not cancelled else self._data.get("last_scan_at"),
        }

    def apply_filesystem_event(self, event_type: str, path: str | Path, old_path: str | Path | None = None) -> dict | None:
        with self._lock:
            return self._apply_filesystem_event(event_type, path, old_path)

    def _apply_filesystem_event(self, event_type: str, path: str | Path, old_path: str | Path | None = None) -> dict | None:
        """Update inventory from one filesystem event without copying media bytes."""
        if event_type == "moved" and old_path:
            old_normalized = normalize_media_path(old_path)
            old_item = self._find_external_by_path(old_normalized)
            destination = Path(path).expanduser()
            destination_type = media_type_for(destination)
            if old_item is not None and destination_type is not None and destination.is_file() and not destination.is_symlink():
                stat = destination.stat()
                old_item.update({
                    "path": normalize_media_path(destination),
                    "name": destination.name,
                    "media_type": destination_type,
                    "extension": destination.suffix.lower(),
                    "size": stat.st_size,
                    "modified_at": stat.st_mtime,
                    "present": True,
                    "missing": False,
                    "last_seen_at": _now(),
                    "updated_at": _now(),
                })
                self._save()
                return dict(old_item)
            if old_item is not None and not old_item.get("missing", False):
                old_item.update({"present": False, "missing": True, "missing_at": _now(), "updated_at": _now()})
                self._save()
            if destination_type is None or not destination.is_file() or destination.is_symlink():
                return None
            return self.register(destination)

        normalized = normalize_media_path(path)
        item = self._find_external_by_path(normalized)
        if event_type == "deleted":
            if item is None or item.get("missing", False):
                return None
            item.update({"present": False, "missing": True, "missing_at": _now(), "updated_at": _now()})
            self._save()
            return dict(item)
        candidate = Path(path).expanduser()
        if media_type_for(candidate) is None or candidate.is_symlink() or not candidate.is_file():
            return None
        return self.register(candidate)

    def set_policy(self, item_id: str, *, delete_protected: bool | None = None, export_protected: bool | None = None) -> dict:
        item = self.get(item_id)
        if item.get("storage_mode") == "external" and export_protected:
            raise MediaLibraryError("Chặn gửi ra ngoài tuyệt đối cần đưa file vào Kho riêng mã hóa.")
        if item.get("storage_mode") == "private_vault" and export_protected is False:
            raise MediaLibraryError("Media trong kho riêng luôn giữ chế độ không xuất.")
        for stored in self._data["items"]:
            if stored.get("id") != item_id:
                continue
            if delete_protected is not None:
                stored["delete_protected"] = bool(delete_protected)
            if export_protected is not None:
                stored["export_protected"] = bool(export_protected)
            stored["updated_at"] = _now()
            self._save()
            return dict(stored)
        raise MediaLibraryError("Không tìm thấy mục media.")

    def mark_private_vault(self, item_id: str, vault_item_id: str) -> dict:
        self.get(item_id)
        for stored in self._data["items"]:
            if stored.get("id") == item_id:
                stored["storage_mode"] = "private_vault"
                stored["vault_item_id"] = vault_item_id
                stored["delete_protected"] = True
                stored["export_protected"] = True
                stored["updated_at"] = _now()
                self._save()
                return dict(stored)
        raise MediaLibraryError("Không tìm thấy mục media.")

    def remove_policy(self, item_id: str) -> dict:
        item = self.get(item_id)
        if item.get("storage_mode") == "private_vault":
            raise MediaLibraryError("Media trong kho riêng không có file ngoài để gỡ bảo vệ.")
        return self.set_policy(item_id, delete_protected=False, export_protected=False)

    def clear_external_inventory(self, remove_delete_protection=None) -> dict:
        """Remove external media from the app inventory without deleting bytes.

        FileSentry-owned delete denies are removed first so clearing the
        inventory cannot leave an untracked folder/file ACL behind. Private
        Vault items remain visible until their encrypted data is handled from
        the Vault screen.
        """
        cleared: list[str] = []
        skipped_private: list[str] = []
        failures: list[dict] = []
        remaining: list[dict] = []
        for item in self._data["items"]:
            if item.get("storage_mode") == "private_vault":
                remaining.append(item)
                skipped_private.append(item.get("id", ""))
                continue
            try:
                if item.get("delete_protected") and Path(item.get("path", "")).is_file():
                    if remove_delete_protection is None:
                        raise MediaLibraryError("Thiếu bộ xử lý để gỡ ACL trước khi xóa metadata.")
                    remove_delete_protection(item["path"])
                cleared.append(item.get("id", ""))
            except Exception as exc:
                remaining.append(item)
                failures.append({"item_id": item.get("id"), "path": item.get("path"), "error": str(exc)})
        # Keep every failed item and commit only successful removals.
        self._data["items"] = remaining
        self._save()
        return {"cleared": cleared, "skipped_private_vault": skipped_private, "failures": failures}

    def refresh_item(self, item_id: str) -> dict:
        item = self.get(item_id)
        if item.get("storage_mode") == "private_vault":
            return item
        path = Path(item.get("path", ""))
        if path.is_file():
            stat = path.stat()
            return self._update_item(item_id, size=stat.st_size, modified_at=stat.st_mtime, present=True, missing=False, last_seen_at=_now())
        return self._update_item(item_id, present=False, missing=True, missing_at=_now())

    def _update_item(self, item_id: str, **updates) -> dict:
        for stored in self._data["items"]:
            if stored.get("id") == item_id:
                stored.update(updates)
                stored["updated_at"] = _now()
                self._save()
                return dict(stored)
        raise MediaLibraryError("Không tìm thấy mục media.")


try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # Optional for environments that only use manual sync.
    FileSystemEventHandler = None
    Observer = None


class _MediaLibraryEventHandler(FileSystemEventHandler if FileSystemEventHandler else object):
    def __init__(self, callback, excludes: list[str]):
        super().__init__() if FileSystemEventHandler else None
        self.callback = callback
        self.excludes = excludes
        self._last: dict[tuple[str, str], float] = {}

    def _allowed(self, path: str) -> bool:
        normalized = normalize_media_path(path)
        return not _is_under(normalized, self.excludes)

    def _emit(self, event_type: str, path: str, old_path: str | None = None) -> None:
        if not self._allowed(path) or (old_path and not self._allowed(old_path)):
            return
        key = (event_type, normalize_media_path(path))
        now = time.monotonic()
        if now - self._last.get(key, 0.0) < 0.75:
            return
        self._last[key] = now
        self.callback(event_type, path, old_path)

    def on_created(self, event):
        if not event.is_directory:
            self._emit("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._emit("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._emit("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._emit("moved", event.dest_path, event.src_path)


class MediaLibraryWatcher:
    """Watch mounted local drives after an initial full synchronization."""

    def __init__(self, callback):
        self.callback = callback
        self.observer = None
        self.roots: list[str] = []
        self.excludes: list[str] = []

    @property
    def available(self) -> bool:
        return bool(Observer and FileSystemEventHandler)

    def start(self, roots: list[str], excludes: list[str]) -> bool:
        self.stop()
        if not self.available:
            return False
        handler = _MediaLibraryEventHandler(self.callback, [normalize_media_path(path) for path in excludes])
        observer = Observer()
        scheduled = 0
        try:
            for root in roots:
                root_path = Path(root)
                if root_path.is_dir() and not _is_under(normalize_media_path(root_path), handler.excludes):
                    observer.schedule(handler, str(root_path), recursive=True)
                    scheduled += 1
        except OSError:
            observer.stop()
            return False
        if not scheduled:
            return False
        observer.start()
        self.observer = observer
        self.roots = list(roots)
        self.excludes = list(excludes)
        return True

    def stop(self) -> None:
        observer = self.observer
        self.observer = None
        if observer:
            observer.stop()
            observer.join(timeout=3)
