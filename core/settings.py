"""Atomic settings and protected-scope management."""

from __future__ import annotations

import json
import os
import time
import uuid
from copy import deepcopy
from pathlib import Path

from .paths import DATA_DIR
from .secure_storage import AppCrypto
from .security import reject_symlink


DEFAULT_SETTINGS = {
    "enabled": True,
    "mode": "protect",
    "theme_mode": "system",
    "onboarding_seen": False,
    "protected_access_locked": False,
    "protected_access_lock_until": None,
    "pause_until": None,
    "include_paths": [],
    "exclude_paths": [],
    "storage_areas": [],
    "ransomware_threshold": 20,
    "ransomware_window_seconds": 5,
    "double_extortion_window_seconds": 120,
    "double_extortion_file_min_events": 5,
    "media_guard": {
        "camera": {
            "mode": "unlocked",
            "access_managed": False,
            "locked_until": None,
            "allowed_sites": [],
            "previous_policy": None,
        },
        "microphone": {
            "mode": "unlocked",
            "access_managed": False,
            "locked_until": None,
            "allowed_sites": [],
            "previous_policy": None,
        },
    },
}


def normalize_path(value: str | Path) -> str:
    return os.path.normcase(str(Path(value).expanduser().resolve(strict=False)))


def path_is_within(candidate: str | Path, root: str | Path) -> bool:
    candidate_path = Path(normalize_path(candidate))
    root_path = Path(normalize_path(root))
    try:
        candidate_path.relative_to(root_path)
        return True
    except ValueError:
        return False


class SettingsStore:
    def __init__(self, path: Path, crypto: AppCrypto | None = None, data_dir: Path | None = None):
        self.path = path
        self.crypto = crypto or AppCrypto(path.parent)
        self.data_dir = Path(data_dir or DATA_DIR)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._settings = self.load()

    def load(self) -> dict:
        settings = deepcopy(DEFAULT_SETTINGS)
        saved = {}
        if self.path.exists():
            saved, encrypted = self.crypto.read_json(self.path)
            settings.update(saved)
        default_media = DEFAULT_SETTINGS["media_guard"]
        saved_media = saved.get("media_guard", {})
        merged_media = {}
        for device in ("camera", "microphone"):
            merged_media[device] = dict(default_media[device])
            merged_media[device].update(saved_media.get(device, {}))
        settings["media_guard"] = merged_media
        settings["include_paths"] = [normalize_path(p) for p in settings["include_paths"]]
        settings["exclude_paths"] = [normalize_path(p) for p in settings["exclude_paths"]]
        storage_areas = []
        for area in settings.get("storage_areas", []):
            if not isinstance(area, dict) or not area.get("path"):
                continue
            storage_areas.append({
                "id": str(area.get("id") or uuid.uuid4().hex),
                "name": str(area.get("name") or Path(area["path"]).name),
                "path": normalize_path(area["path"]),
                "created_at": str(area.get("created_at") or ""),
            })
        settings["storage_areas"] = storage_areas
        self._settings = settings
        if not self.path.exists() or not encrypted:
            self.save()
        return dict(self._settings)

    def save(self, updates: dict | None = None) -> dict:
        if updates:
            self._settings.update(updates)
        self._settings["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.crypto.write_json(self.path, self._settings)
        return dict(self._settings)

    @property
    def data(self) -> dict:
        return dict(self._settings)

    def is_active(self) -> bool:
        pause_until = self._settings.get("pause_until")
        if pause_until and float(pause_until) > time.time():
            return False
        if pause_until:
            self.save({"pause_until": None})
        return bool(self._settings.get("enabled", False))

    def effective_paths(self) -> tuple[list[str], list[str]]:
        includes = [p for p in self._settings["include_paths"] if Path(p).exists()]
        internal_data = normalize_path(self.data_dir)
        excludes = list(self._settings["exclude_paths"])
        if internal_data not in excludes:
            excludes.append(internal_data)
        return includes, excludes

    def in_scope(self, path: str | Path) -> bool:
        candidate = normalize_path(path)
        includes, excludes = self.effective_paths()
        if not any(path_is_within(candidate, root) for root in includes):
            return False
        return not any(path_is_within(candidate, root) for root in excludes)

    def add_path(self, kind: str, path: str | Path) -> None:
        if kind not in {"include", "exclude"}:
            raise ValueError("Loại khu vực không hợp lệ.")
        candidate = reject_symlink(Path(path).expanduser())
        if candidate.exists() and not candidate.is_dir():
            raise ValueError("Khu vực bảo vệ phải là thư mục.")
        normalized = normalize_path(path)
        key = "include_paths" if kind == "include" else "exclude_paths"
        values = list(self._settings[key])
        if len(values) >= (64 if kind == "include" else 128):
            raise ValueError("Đã đạt giới hạn số khu vực cấu hình.")
        if len(normalized) > 32760:
            raise ValueError("Đường dẫn quá dài.")
        if normalized not in values:
            values.append(normalized)
            self.save({key: values})

    def create_storage_area(self, parent: str | Path, name: str = "FileSentry Protected Storage") -> dict:
        """Create a dedicated managed folder without touching existing files."""
        parent_path = reject_symlink(Path(parent).expanduser(), "Không tạo kho trong symbolic link.")
        if not parent_path.is_dir():
            raise ValueError("Thư mục gốc lưu trữ không tồn tại hoặc không phải thư mục.")
        folder_name = str(name or "").strip()
        if (
            not folder_name
            or folder_name in {".", ".."}
            or "/" in folder_name
            or "\\" in folder_name
            or ":" in folder_name
            or len(folder_name) > 96
        ):
            raise ValueError("Tên kho lưu trữ không hợp lệ. Chỉ nhập tên một thư mục, không nhập đường dẫn.")
        storage_path = parent_path / folder_name
        if storage_path.is_symlink():
            raise ValueError("Không tạo kho lưu trữ tại symbolic link.")
        normalized = normalize_path(storage_path)
        data_root = normalize_path(self.data_dir)
        if path_is_within(normalized, data_root) or path_is_within(data_root, normalized):
            raise ValueError("Không thể dùng thư mục dữ liệu nội bộ của FileSentry làm kho lưu trữ.")
        if any(path_is_within(normalized, excluded) for excluded in self._settings["exclude_paths"]):
            raise ValueError("Kho lưu trữ nằm trong khu vực loại trừ; hãy chọn vị trí khác.")
        existing = next((area for area in self._settings["storage_areas"] if area["path"] == normalized), None)
        if existing:
            return dict(existing)
        if storage_path.exists() and not storage_path.is_dir():
            raise ValueError("Tên kho lưu trữ đã trùng với một file.")
        storage_path.mkdir(parents=False, exist_ok=True)
        record = {
            "id": uuid.uuid4().hex,
            "name": folder_name,
            "path": normalized,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._settings["storage_areas"] = [*self._settings["storage_areas"], record]
        self.save({"storage_areas": self._settings["storage_areas"]})
        return dict(record)

    def get_storage_area(self, area_id: str) -> dict:
        for area in self._settings["storage_areas"]:
            if area.get("id") == str(area_id):
                return dict(area)
        raise ValueError("Không tìm thấy kho lưu trữ bảo vệ.")

    def remove_storage_area(self, area_id: str) -> dict:
        area = self.get_storage_area(area_id)
        self.save({"storage_areas": [item for item in self._settings["storage_areas"] if item.get("id") != str(area_id)]})
        return area

    def remove_path(self, kind: str, path: str | Path) -> None:
        if kind not in {"include", "exclude"}:
            raise ValueError("Loại khu vực không hợp lệ.")
        normalized = normalize_path(path)
        key = "include_paths" if kind == "include" else "exclude_paths"
        self.save({key: [item for item in self._settings[key] if item != normalized]})
