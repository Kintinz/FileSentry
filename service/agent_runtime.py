"""Fail-closed service runtime using the machine-scope profile and Named Pipe."""

from __future__ import annotations

from pathlib import Path

from core.controller import FileSentryController

from .auth_broker import ServiceAuthBroker
from .data_profile import ServiceDataProfile
from .named_pipe import NamedPipeConfig, NamedPipeServer


class AgentRuntime:
    READ_ONLY_ACTIONS = {
        "status",
        "network_state",
        "persistence_state",
        "health_state",
        "access_snapshot",
        "media_library_state",
        "folder_lock_state",
        "protected_storage_state",
    }
    CAPABILITY_RESOURCES = {
        "protection",
        "scope",
        "vault",
        "media.camera",
        "media.microphone",
        "media.library",
        "folder.lock",
        "quarantine.restore",
        "uninstall",
    }
    MUTATION_RESOURCES = {
        "set_protection": "protection",
        "pause": "protection",
        "lock_protected_access": "scope",
        "unlock_protected_access": "scope",
        "add_scope": "scope",
        "remove_scope": "scope",
        "create_protected_storage": "scope",
        "remove_protected_storage": "scope",
        "unlock_vault_session": "vault",
        "scan_media_library": "media.library",
        "register_media_file": "media.library",
        "set_media_file_policy": "media.library",
        "secure_media_file": "media.library",
        "remove_media_file_policy": "media.library",
        "clear_media_library_inventory": "media.library",
        "lock_folder": "folder.lock",
        "unlock_folder": "folder.lock",
        "verify_folder_lock_integrity": "folder.lock",
        "emergency_unlock_all_folders": "folder.lock",
        "prepare_uninstall": "uninstall",
    }

    def __init__(self, data_root: str | Path, allowed_sid: str, shared_secret: bytes, pipe_name: str):
        self.profile = ServiceDataProfile(data_root, protect=True)
        self.controller = FileSentryController(data_root=self.profile.root, dpapi_scope="machine")
        self.auth_broker = ServiceAuthBroker(self.controller.auth)
        self.server = NamedPipeServer(
            shared_secret,
            allowed_sid,
            self._handle_request,
            NamedPipeConfig(name=pipe_name),
        )

    def start(self) -> None:
        try:
            self.server.start()
        except Exception:
            self.controller.stop()
            raise

    def stop(self) -> None:
        self.server.stop()
        self.controller.stop()

    def _handle_request(self, _client_id: str, request: dict) -> dict:
        client_id = str(_client_id)
        action = str(request.get("action", ""))
        if action == "auth_begin":
            return self.auth_broker.begin(client_id, str(request.get("username", "")))
        if action == "auth_proof":
            return self.auth_broker.verify(
                client_id,
                str(request.get("challenge_id", "")),
                str(request.get("proof", "")),
            )
        if action == "issue_capability":
            resource = str(request.get("resource", ""))
            if resource not in self.CAPABILITY_RESOURCES:
                raise PermissionError("Resource capability không được phép.")
            token = self.auth_broker.issue_capability(
                client_id,
                str(request.get("session_token", "")),
                resource,
                int(request.get("ttl_seconds", 300)),
            )
            return {"resource": resource, "capability": token}
        if action == "set_media_mode":
            kind = str(request.get("kind", ""))
            resource = f"media.{kind}"
            if kind not in {"camera", "microphone"}:
                raise ValueError("Media resource không hợp lệ.")
            self._require_capability(client_id, request, resource)
            self.controller.set_media_mode(
                kind,
                str(request.get("mode", "")),
                request.get("minutes"),
                username=f"service:{client_id}",
            )
            return {"ok": True, "resource": resource}
        if action == "media_library_state":
            return self.controller.media_library_state()
        if action == "folder_lock_state":
            return self.controller.folder_lock_state()
        if action == "protected_storage_state":
            return self.controller.protected_storage_state()
        if action in self.MUTATION_RESOURCES:
            resource = self.MUTATION_RESOURCES[action]
            self._require_capability(client_id, request, resource)
            username = f"service:{client_id}"
            if action == "set_protection":
                self.controller.set_protection(bool(request.get("enabled")), username=username)
            elif action == "pause":
                self.controller.pause(int(request.get("minutes", 1)), username=username)
            elif action == "lock_protected_access":
                self.controller.lock_protected_access(request.get("minutes"), username=username)
            elif action == "unlock_protected_access":
                self.controller.unlock_protected_access(username=username)
            elif action in {"add_scope", "remove_scope"}:
                kind = str(request.get("kind", ""))
                if kind not in {"include", "exclude"}:
                    raise ValueError("Scope kind không hợp lệ.")
                method = self.controller.add_path if action == "add_scope" else self.controller.remove_path
                method(kind, str(request.get("path", "")), username=username)
            elif action == "create_protected_storage":
                return self.controller.create_protected_storage(
                    str(request.get("parent", "")),
                    str(request.get("name", "FileSentry Protected Storage")),
                    username=username,
                )
            elif action == "remove_protected_storage":
                return self.controller.remove_protected_storage(str(request.get("area_id", "")), username=username)
            elif action == "unlock_vault_session":
                return self.controller.unlock_vault_session(username=username)
            elif action == "scan_media_library":
                return self.controller.scan_media_library(username=username)
            elif action == "register_media_file":
                return self.controller.register_media_file(str(request.get("path", "")), username=username)
            elif action == "set_media_file_policy":
                return self.controller.set_media_file_policy(
                    str(request.get("item_id", "")),
                    delete_protected=request.get("delete_protected"),
                    export_protected=request.get("export_protected"),
                    username=username,
                )
            elif action == "secure_media_file":
                return self.controller.secure_media_file(str(request.get("item_id", "")), username=username)
            elif action == "remove_media_file_policy":
                return self.controller.remove_media_file_policy(str(request.get("item_id", "")), username=username)
            elif action == "clear_media_library_inventory":
                return self.controller.clear_media_library_inventory(username=username)
            elif action == "lock_folder":
                return self.controller.lock_folder(str(request.get("path", "")), username=username)
            elif action == "unlock_folder":
                return self.controller.unlock_folder(str(request.get("lock_id", "")), username=username)
            elif action == "verify_folder_lock_integrity":
                return self.controller.verify_folder_lock_integrity(username=username)
            elif action == "emergency_unlock_all_folders":
                return self.controller.emergency_unlock_all_folders(username=username)
            elif action == "prepare_uninstall":
                return self.controller.prepare_uninstall(username=username)
            return {"ok": True, "action": action}
        if action not in self.READ_ONLY_ACTIONS:
            raise PermissionError("Service đang fail-closed: thao tác thay đổi cần handler gắn capability.")
        if action == "status":
            return self.controller.status()
        if action == "network_state":
            return self.controller.network_state()
        if action == "persistence_state":
            return self.controller.persistence_state()
        if action == "health_state":
            return self.controller.health_state()
        if action == "media_library_state":
            return self.controller.media_library_state()
        if action == "folder_lock_state":
            return self.controller.folder_lock_state()
        return {"access": self.controller.access_snapshot()}

    def _require_capability(self, client_id: str, request: dict, resource: str) -> None:
        capability = str(request.get("capability", ""))
        if not self.auth_broker.require_capability(client_id, capability, resource):
            raise PermissionError(f"Capability không hợp lệ cho resource: {resource}.")
