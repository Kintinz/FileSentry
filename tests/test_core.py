import os
import tempfile
import time
import unittest
import hashlib
import uuid
from pathlib import Path
from threading import Event
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidTag

from core.auth import AuthManager, AuthError, DEFAULT_PASSWORD
from core.auth_session import AuthSession
from core.access_gateway import AccessGateway
from core.branding import ICON_PATH, PRODUCT_EXE_NAME, PRODUCT_NAME, runtime_icon_path
from core.controller import FileSentryController
from core.file_signals import analyze_file
from core.event_correlation import correlate_double_extortion
from core.folder_lock import FolderLockError, FolderLockManager
from core.media_guard import WindowsPrivacyAdapter, normalize_origin
from core.media_library import MediaLibraryError, MediaLibraryManager, media_type_for
from core.media_protection import MediaFileProtection, MediaProtectionError
from core.camera_mic_guard import CameraMicGuard
from core.network_monitor import _is_public, _risk_indicators
from core.uninstall import UninstallError, UninstallManager
from core.intrusion_log import IntrusionChain
from core.db import Database
from core.incident_report import IncidentReportBuilder
from core.vault import VaultManager
from core.versioning import VersionStore
from core.secure_storage import AppCrypto
from core.settings import SettingsStore
from service.ipc_protocol import IpcAuthenticator
from updater.manifest import sign_manifest, verify_manifest
from service.data_profile import ServiceDataMigrator, ServiceDataProfile
from service.named_pipe import NamedPipeClient, NamedPipeConfig, NamedPipeServer, current_user_sid
from service.auth_broker import ServiceAuthBroker
from service.agent_runtime import AgentRuntime


class CoreTests(unittest.TestCase):
    def test_product_identity_and_icon(self):
        self.assertEqual(PRODUCT_NAME, "FileSentry Sentinel")
        self.assertEqual(PRODUCT_EXE_NAME, "FileSentrySentinel.exe")
        self.assertTrue(ICON_PATH.is_file())
        self.assertTrue(runtime_icon_path().is_file())
        self.assertGreater(ICON_PATH.stat().st_size, 100)

    def test_ipc_challenge_is_one_time_and_client_bound(self):
        authenticator = IpcAuthenticator(b"s" * 32, challenge_ttl=5)
        request = {"action": "status", "request_id": "r-1"}
        challenge = authenticator.issue_challenge("ui")
        mac = authenticator.sign_request("ui", challenge, request)
        self.assertTrue(authenticator.authenticate("ui", challenge, request, mac))
        self.assertFalse(authenticator.authenticate("ui", challenge, request, mac))

        other = authenticator.issue_challenge("ui")
        other_mac = authenticator.sign_request("ui", other, request)
        self.assertFalse(authenticator.authenticate("tray", other, request, other_mac))

    def test_ipc_rejects_oversized_request(self):
        authenticator = IpcAuthenticator(b"s" * 32)
        challenge = authenticator.issue_challenge("ui")
        oversized = {"payload": "x" * (256 * 1024)}
        with self.assertRaises(ValueError):
            authenticator.sign_request("ui", challenge, oversized)

    def test_service_password_proof_and_capability_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = AuthManager(Path(directory) / "auth.json")
            broker = ServiceAuthBroker(auth)
            challenge = broker.begin("ui", "admin")
            proof = ServiceAuthBroker.derive_proof(DEFAULT_PASSWORD, challenge, "ui")
            session = broker.verify("ui", challenge["challenge_id"], proof)
            self.assertTrue(broker.require_session("ui", session["session_token"], "admin"))
            capability = broker.issue_capability("ui", session["session_token"], "vault")
            self.assertTrue(broker.require_capability("ui", capability, "vault"))
            self.assertFalse(broker.require_capability("ui", capability, "media.camera"))
            self.assertFalse(broker.require_capability("other", capability, "vault"))

    def test_agent_mutations_require_resource_capability(self):
        class FakeController:
            def __init__(self):
                self.calls = []

            def set_protection(self, enabled, username):
                self.calls.append(("set_protection", enabled, username))

        with tempfile.TemporaryDirectory() as directory:
            auth = AuthManager(Path(directory) / "auth.json")
            broker = ServiceAuthBroker(auth)
            runtime = AgentRuntime.__new__(AgentRuntime)
            runtime.auth_broker = broker
            runtime.controller = FakeController()
            challenge = broker.begin("ui", "admin")
            proof = ServiceAuthBroker.derive_proof(DEFAULT_PASSWORD, challenge, "ui")
            session = broker.verify("ui", challenge["challenge_id"], proof)
            with self.assertRaises(PermissionError):
                runtime._handle_request("ui", {"action": "set_protection", "enabled": True})
            capability = broker.issue_capability("ui", session["session_token"], "protection")
            result = runtime._handle_request("ui", {
                "action": "set_protection",
                "enabled": True,
                "capability": capability,
            })
            self.assertTrue(result["ok"])
            self.assertEqual(runtime.controller.calls[0][0], "set_protection")

    @unittest.skipUnless(os.name == "nt", "V2 Windows profile/pipe tests require Windows")
    def test_service_profile_migration_is_non_destructive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "v1"
            destination = root / "service"
            backup = root / "backup"
            (source / "logs").mkdir(parents=True)
            (source / "vault_store").mkdir(parents=True)
            old_crypto = AppCrypto(source)
            old_crypto.write_json(source / "settings.json", {"enabled": True, "scope": ["C:/Protected"]})
            payload = root / "payload.bin"
            payload.write_bytes(b"service migration payload")
            item_id = "a" * 32
            old_crypto.encrypt_file(payload, source / "vault_store" / f"{item_id}.vault", f"vault:{item_id}")
            old_chain = IntrusionChain(source / "logs" / "intrusion_chain.log", old_crypto)
            old_chain.append("audit", {"action": "migration-test"})
            old_database = Database(source / "filesentry.db", crypto=old_crypto, chain_path=source / "logs" / "intrusion_chain.log")
            old_database.record_event({"event_type": "migration", "path": "C:/migration-test.txt"})

            result = ServiceDataMigrator(source, destination, backup, protect=False).migrate()
            self.assertTrue(Path(result["backup"]).is_dir())
            self.assertTrue((source / "settings.json").exists())
            new_profile = ServiceDataProfile(destination, protect=False)
            settings, encrypted = new_profile.crypto.read_json(destination / "settings.json")
            self.assertTrue(encrypted)
            self.assertTrue(settings["enabled"])
            restored = root / "restored.bin"
            new_profile.crypto.decrypt_file(destination / "vault_store" / f"{item_id}.vault", restored, f"vault:{item_id}")
            self.assertEqual(restored.read_bytes(), payload.read_bytes())
            new_database = Database(destination / "filesentry.db", crypto=new_profile.crypto, chain_path=destination / "logs" / "intrusion_chain.log")
            self.assertEqual(len(new_database.events()), 1)
            self.assertTrue(IntrusionChain(destination / "logs" / "intrusion_chain.log", new_profile.crypto).verify()["valid"])

    @unittest.skipUnless(os.name == "nt", "Service controller profile requires Windows DPAPI")
    def test_controller_can_open_machine_scope_service_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = FileSentryController(data_root=Path(directory) / "service", dpapi_scope="machine")
            try:
                self.assertTrue((Path(directory) / "service" / "auth.json").exists())
                self.assertEqual(controller.data_root, Path(directory) / "service")
            finally:
                controller.stop()

    @unittest.skipUnless(os.name == "nt", "Named Pipe tests require Windows")
    def test_named_pipe_authenticates_peer_and_request(self):
        secret = b"p" * 32
        config = NamedPipeConfig(name=rf"\\.\pipe\FileSentryTest-{uuid.uuid4().hex}")
        server = NamedPipeServer(secret, current_user_sid(), lambda _client, request: {"echo": request.get("value")}, config)
        server.start()
        self.assertTrue(server.ready_event.wait(2))
        try:
            response = NamedPipeClient(secret, "ui", config).request({"value": "ok"})
            self.assertEqual(response, {"ok": True, "result": {"echo": "ok"}})
            failed = NamedPipeClient(b"q" * 32, "ui", config).request({"value": "bad-mac"})
            self.assertEqual(failed["error"], "authentication_failed")
        finally:
            server.stop()

    def test_signed_update_manifest_verifies_artifact_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "FileSentry.exe"
            artifact.write_bytes(b"signed release artifact")
            private = Ed25519PrivateKey.generate()
            private_bytes = private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            public_bytes = private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            manifest = {
                "manifest_version": 1,
                "publisher": "FileSentry",
                "version": "0.2.1",
                "artifact_name": artifact.name,
                "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            signed = sign_manifest(manifest, private_bytes)
            result = verify_manifest(signed, artifact, public_bytes, current_version="0.2.0")
            self.assertTrue(result["valid"])
            self.assertEqual(result["version"], "0.2.1")

            artifact.write_bytes(b"tampered artifact")
            with self.assertRaises(ValueError):
                verify_manifest(signed, artifact, public_bytes, current_version="0.2.0")

    def test_access_gateway_grant_expires_and_can_be_revoked(self):
        gateway = AccessGateway(default_minutes=1)
        token = gateway.unlock("camera", minutes=1)
        self.assertTrue(gateway.is_unlocked("camera"))
        self.assertTrue(gateway.is_unlocked("camera", token))
        self.assertFalse(gateway.is_unlocked("microphone", token))
        self.assertFalse(gateway.is_unlocked("camera", "wrong-token"))
        gateway.lock("camera")
        self.assertFalse(gateway.is_unlocked("camera"))

    def test_auth_session_is_username_scoped_and_can_clear(self):
        session = AuthSession(ttl_seconds=60)
        session.open("admin")
        self.assertTrue(session.is_valid("admin"))
        self.assertFalse(session.is_valid("other"))
        session.clear()
        self.assertFalse(session.is_valid("admin"))

    def test_version_metadata_is_encrypted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crypto = AppCrypto(root)
            store = VersionStore(root / "version.json", crypto)
            self.assertEqual(store.data["vault_format_version"], 1)
            self.assertTrue((root / "version.json").read_text(encoding="utf-8").startswith("FS1:"))

    def test_seeded_auth_and_password_change(self):
        with tempfile.TemporaryDirectory() as directory:
            auth_path = Path(directory) / "auth.json"
            manager = AuthManager(auth_path)
            self.assertEqual(manager.authenticate("admin", DEFAULT_PASSWORD), (True, True))
            manager.change_password("admin", DEFAULT_PASSWORD, "A-secure-pass-2026")
            self.assertEqual(manager.authenticate("admin", "A-secure-pass-2026"), (True, False))
            self.assertTrue(auth_path.read_text(encoding="utf-8").startswith("FS1:"))

    def test_auth_lockout_state_survives_manager_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            auth_path = Path(directory) / "auth.json"
            first = AuthManager(auth_path)
            for _ in range(5):
                self.assertEqual(first.authenticate("admin", "wrong-password"), (False, False))
            second = AuthManager(auth_path)
            self.assertEqual(second.authenticate("admin", DEFAULT_PASSWORD), (False, False))

    def test_secure_file_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crypto = AppCrypto(root)
            source = root / "source.bin"
            encrypted = root / "encrypted.bin"
            restored = root / "restored.bin"
            source.write_bytes(b"FileSentry secure payload" * 1000)
            crypto.encrypt_file(source, encrypted, "test")
            self.assertNotEqual(source.read_bytes(), encrypted.read_bytes())
            crypto.decrypt_file(encrypted, restored, "test")
            self.assertEqual(source.read_bytes(), restored.read_bytes())

    def test_media_library_classifies_and_encrypts_policy_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "private-photo.jpg"
            image.write_bytes(b"image-bytes")
            self.assertEqual(media_type_for(image), "image")
            self.assertEqual(media_type_for(root / "recording.wav"), "audio")
            manager = MediaLibraryManager(root, AppCrypto(root))
            item = manager.register(image)
            self.assertEqual(item["media_type"], "image")
            updated = manager.set_policy(item["id"], delete_protected=True)
            self.assertTrue(updated["delete_protected"])
            with self.assertRaises(MediaLibraryError):
                manager.set_policy(item["id"], export_protected=True)
            raw = (root / "media_library.json").read_text(encoding="utf-8")
            self.assertTrue(raw.startswith("FS1:"))
            self.assertNotIn(str(image), raw)

    def test_media_library_scan_syncs_additions_and_removals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            media_root = root / "media"
            media_root.mkdir()
            first = media_root / "first.jpg"
            first.write_bytes(b"first")
            manager = MediaLibraryManager(root / "app-data", AppCrypto(root / "app-data"))

            initial = manager.scan([str(media_root)])
            self.assertEqual(initial["registered"], 1)
            second = media_root / "second.mp4"
            second.write_bytes(b"second")
            first.unlink()

            result = manager.scan([str(media_root)])
            self.assertEqual(result["registered"], 1)
            self.assertEqual(result["removed"], 1)
            items = manager.list_items()
            self.assertTrue(any(item["name"] == "second.mp4" and item["present"] for item in items))
            self.assertTrue(any(item["name"] == "first.jpg" and item["missing"] for item in items))

    def test_media_library_scan_reports_progress_and_can_cancel_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            media_root = root / "media"
            media_root.mkdir()
            (media_root / "progress.jpg").write_bytes(b"progress")
            manager = MediaLibraryManager(root / "app-data", AppCrypto(root / "app-data"))
            progress = []
            result = manager.scan([str(media_root)], progress_callback=progress.append)
            self.assertFalse(result["cancelled"])
            self.assertTrue(any(item.get("phase") == "processing" and item.get("total") == 1 for item in progress))
            self.assertEqual(progress[-1]["percent"], 100)

            cancelled_root = root / "cancelled"
            cancelled_root.mkdir()
            (cancelled_root / "cancelled.mp3").write_bytes(b"cancelled")
            cancel = Event()
            cancel.set()
            cancelled = manager.scan([str(cancelled_root)], cancel_event=cancel)
            self.assertTrue(cancelled["cancelled"])
            self.assertFalse(any(item["name"] == "cancelled.mp3" for item in manager.list_items()))

    def test_media_library_clear_inventory_keeps_external_bytes_and_private_vault_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "keep-photo.jpg"
            external.write_bytes(b"real-photo-bytes")
            manager = MediaLibraryManager(root / "app-data", AppCrypto(root / "app-data"))
            external_item = manager.register(external)
            private_source = root / "private-audio.mp3"
            private_source.write_bytes(b"encrypted-audio-reference")
            private_item = manager.register(private_source)
            manager.mark_private_vault(private_item["id"], "a" * 32)

            result = manager.clear_external_inventory()

            self.assertEqual(result["cleared"], [external_item["id"]])
            self.assertEqual(result["failures"], [])
            self.assertEqual(result["skipped_private_vault"], [private_item["id"]])
            self.assertTrue(external.exists())
            remaining = manager.list_items()
            self.assertEqual([item["id"] for item in remaining], [private_item["id"]])

    def test_vault_read_bytes_is_bounded_and_does_not_restore_external_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "preview.jpg"
            source.write_bytes(b"preview-bytes")
            vault = VaultManager(AppCrypto(root), root=root)
            manifest = vault.import_file(source, remove_source=True, export_blocked=True)

            self.assertEqual(vault.read_bytes(manifest["id"]), b"preview-bytes")
            self.assertFalse((root / "preview.jpg").exists())
            with self.assertRaises(ValueError):
                vault.read_bytes(manifest["id"], max_bytes=4)

    def test_folder_lock_manifest_is_encrypted_and_acl_is_applied_after_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            manager = FolderLockManager(root / "app-data", AppCrypto(root / "app-data"))
            fake_dacl = MagicMock()
            fake_sid = object()
            with patch.object(manager, "_current_sid", return_value=(fake_sid, "S-1-5-21-test")), \
                 patch.object(manager, "_security_descriptor", return_value=("D:(A;;FA;;;WD)", fake_dacl, False, True)), \
                 patch.object(manager, "_set_dacl") as set_dacl:
                item = manager.lock_folder(target)
            self.assertEqual(item["status"], "locked")
            fake_dacl.AddAccessDeniedAceEx.assert_called_once()
            set_dacl.assert_called_once()
            raw = (root / "app-data" / "folder_locks.json").read_text(encoding="utf-8")
            self.assertTrue(raw.startswith("FS1:"))
            self.assertNotIn(str(target), raw)

    def test_folder_lock_never_applies_acl_when_backup_write_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            manager = FolderLockManager(root / "app-data", AppCrypto(root / "app-data"))
            fake_dacl = MagicMock()
            with patch.object(manager, "_current_sid", return_value=(object(), "S-1-5-21-test")), \
                 patch.object(manager, "_security_descriptor", return_value=("D:(A;;FA;;;WD)", fake_dacl, False, True)), \
                 patch.object(manager, "_save", side_effect=OSError("disk full")), \
                 patch.object(manager, "_set_dacl") as set_dacl:
                with self.assertRaises(FolderLockError):
                    manager.lock_folder(target)
            set_dacl.assert_not_called()

    def test_uninstall_blocks_when_folder_lock_release_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = UninstallManager(Path(directory) / "FileSentry")
            fake_locks = MagicMock()
            fake_locks.list_locks.return_value = [{"id": "lock-1", "status": "locked", "original_path": "C:/private"}]
            fake_locks.unlock_all_for_uninstall.side_effect = FolderLockError("cannot restore")
            with self.assertRaises(UninstallError):
                manager.release_folder_locks(fake_locks)

    def test_media_library_event_watcher_updates_create_delete_and_move(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "event.jpg"
            source.write_bytes(b"event")
            manager = MediaLibraryManager(root / "app-data", AppCrypto(root / "app-data"))
            manager.apply_filesystem_event("created", source)
            self.assertTrue(manager.list_items()[0]["present"])
            destination = root / "renamed.jpg"
            source.rename(destination)
            manager.apply_filesystem_event("moved", destination, source)
            self.assertEqual(manager.list_items()[0]["path"], str(destination).lower())
            destination.unlink()
            manager.apply_filesystem_event("deleted", destination)
            self.assertTrue(manager.list_items()[0]["missing"])

    def test_vault_can_move_source_after_authenticated_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "private-video.mp4"
            source.write_bytes(b"video-bytes")
            vault = VaultManager(AppCrypto(root), root=root)
            manifest = vault.import_file(source, remove_source=True)
            self.assertFalse(source.exists())
            restored = root / "restored-video.mp4"
            vault.restore(manifest["id"], str(restored))
            self.assertEqual(restored.read_bytes(), b"video-bytes")

    def test_vault_export_blocked_item_cannot_be_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "private-audio.mp3"
            source.write_bytes(b"audio-bytes")
            vault = VaultManager(AppCrypto(root), root=root)
            manifest = vault.import_file(source, remove_source=True, export_blocked=True)
            with self.assertRaises(PermissionError):
                vault.restore(manifest["id"], str(root / "restored-audio.mp3"))

    @unittest.skipUnless(os.name == "nt", "Windows ACL guard requires Windows")
    def test_media_file_protection_rejects_invalid_target_without_touching_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(MediaProtectionError):
                MediaFileProtection().set_delete_protected(root / "missing.jpg", True)

    def test_scope_include_and_exclude(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            excluded = root / "cache"
            excluded.mkdir(parents=True)
            store = SettingsStore(Path(directory) / "settings.json")
            store.add_path("include", root)
            store.add_path("exclude", excluded)
            self.assertTrue(store.in_scope(root / "document.txt"))
            self.assertFalse(store.in_scope(excluded / "cache.bin"))

    def test_protected_storage_area_is_created_and_removal_keeps_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = SettingsStore(root / "settings.json", data_dir=root / "app-data")
            parent = root / "protected"
            parent.mkdir()
            area = store.create_storage_area(parent, "Private Media")
            self.assertTrue(Path(area["path"]).is_dir())
            self.assertEqual(store.get_storage_area(area["id"])["name"], "Private Media")
            removed = store.remove_storage_area(area["id"])
            self.assertEqual(removed["path"], area["path"])
            self.assertTrue(Path(area["path"]).is_dir())

    def test_protected_access_lock_and_pause_state(self):
        controller = FileSentryController()
        original = controller.settings.data
        try:
            controller.lock_protected_access(1, "admin")
            self.assertTrue(controller.status()["access_locked"])
            controller.unlock_protected_access("admin")
            self.assertFalse(controller.status()["access_locked"])
            controller.pause(1, "admin")
            self.assertFalse(controller.status()["active"])
        finally:
            controller.stop()
            controller.settings.save(original)

    def test_media_origin_normalization(self):
        self.assertEqual(normalize_origin("example.com"), "https://example.com")
        self.assertEqual(normalize_origin("HTTPS://Example.com"), "https://example.com")
        with self.assertRaises(ValueError):
            normalize_origin("https://example.com/path")
        self.assertTrue(WindowsPrivacyAdapter.is_force_denied({"app_policy": 2, "desktop_policy": "Allow"}))
        self.assertTrue(WindowsPrivacyAdapter.is_force_denied({"app_policy": None, "desktop_policy": "Deny"}))
        self.assertFalse(WindowsPrivacyAdapter.is_force_denied({"app_policy": None, "desktop_policy": "Allow"}))

    def test_auth_rejects_weak_new_password(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = AuthManager(Path(directory) / "auth.json")
            with self.assertRaises(AuthError):
                manager.change_password("admin", DEFAULT_PASSWORD, "short")

    def test_quarantine_rejects_symlink_and_traversal_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("secret", encoding="utf-8")
            controller = FileSentryController()
            manager = controller.quarantine
            try:
                with self.assertRaises(ValueError):
                    manager.restore("../auth.json")
                if hasattr(source, "symlink_to"):
                    link = root / "link.txt"
                    try:
                        link.symlink_to(source)
                    except (OSError, NotImplementedError):
                        link = None
                    if link is not None:
                        with self.assertRaises(ValueError):
                            manager.quarantine_file(str(link), "test")
            finally:
                controller.stop()

    def test_file_signals_are_local_and_explainable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invoice.pdf.exe"
            path.write_bytes(b"not-a-real-executable")
            codes = {item["code"] for item in analyze_file(path)}
            self.assertIn("double_extension", codes)
            self.assertNotIn("embedded_pe", codes)

    def test_network_indicators_are_conservative(self):
        self.assertTrue(_is_public("8.8.8.8"))
        self.assertFalse(_is_public("192.168.1.10"))
        listener = {
            "direction": "inbound_listener",
            "wildcard_local": True,
            "local_port": 31337,
            "is_external": False,
        }
        codes = {item["code"] for item in _risk_indicators(listener)}
        self.assertIn("unexpected_listener", codes)

    def test_double_extortion_correlation_requires_both_event_streams(self):
        file_events = [
            {"event_type": "created", "path": f"C:/Docs/file-{index}.txt", "_observed_at": 100 + index}
            for index in range(5)
        ]
        self.assertIsNone(correlate_double_extortion(file_events, [], 110))
        network_event = {
            "event_type": "network_connection",
            "path": "network://tcp/203.0.113.7:4444",
            "_observed_at": 105,
            "details": {"is_external": True, "remote_port": 4444},
        }
        self.assertIsNone(correlate_double_extortion([], [network_event], 110))

    def test_double_extortion_correlation_returns_explainable_signal(self):
        file_events = [
            {"event_type": "created", "path": f"C:/Docs/file-{index}.txt", "_observed_at": 100 + index}
            for index in range(5)
        ]
        network_event = {
            "event_type": "network_connection",
            "path": "network://tcp/203.0.113.7:4444",
            "_observed_at": 105,
            "details": {
                "is_external": True,
                "remote_address": "203.0.113.7",
                "remote_port": 4444,
                "process_path": "C:/Users/test/AppData/Local/rclone.exe",
            },
            "risks": [{"code": "writable_process_network", "title": "Ứng dụng từ thư mục người dùng kết nối Internet"}],
        }
        result = correlate_double_extortion(file_events, [network_event], 110)
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "warning")
        self.assertEqual(result["destructive_events_count"], 5)
        self.assertIn("203.0.113.7", result["network_endpoints"][0])
        self.assertTrue(result["fingerprint"])

    def test_double_extension_can_correlate_with_risky_network(self):
        file_events = [{
            "event_type": "created",
            "path": "C:/Users/test/Downloads/invoice.pdf.exe",
            "double_extension": True,
            "_observed_at": 100,
        }]
        network_event = {
            "event_type": "network_connection",
            "path": "network://tcp/203.0.113.8:443",
            "_observed_at": 105,
            "details": {"is_external": True, "remote_port": 443},
            "risks": [{"code": "unexpected_process", "title": "Kết nối cần kiểm tra"}],
        }
        result = correlate_double_extortion(file_events, [network_event], 110)
        self.assertIsNotNone(result)
        self.assertEqual(result["double_extension_count"], 1)
        self.assertEqual(result["destructive_events_count"], 1)

    def test_uninstall_refuses_source_mode(self):
        with self.assertRaises(UninstallError):
            UninstallManager().executable_path()

    def test_vault_round_trip_preserves_source_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crypto = AppCrypto(root)
            source = root / "private.txt"
            restored = root / "restored.txt"
            source.write_text("vault payload", encoding="utf-8")
            gateway = AccessGateway()
            manager = VaultManager(crypto=crypto, root=root, access_gateway=gateway)
            with self.assertRaises(PermissionError):
                manager.import_file(str(source))
            gateway.unlock("vault")
            item = manager.import_file(str(source))
            self.assertEqual(source.read_text(encoding="utf-8"), "vault payload")
            manager.restore(item["id"], str(restored))
            self.assertEqual(restored.read_text(encoding="utf-8"), "vault payload")

    def test_vault_ciphertext_is_bound_to_item_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crypto = AppCrypto(root)
            first_source = root / "first.txt"
            second_source = root / "second.txt"
            first_source.write_text("first", encoding="utf-8")
            second_source.write_text("second", encoding="utf-8")
            gateway = AccessGateway()
            manager = VaultManager(crypto=crypto, root=root, access_gateway=gateway)
            gateway.unlock("vault")
            first = manager.import_file(str(first_source))
            second = manager.import_file(str(second_source))
            first_store = Path(first["stored_path"])
            second_store = Path(second["stored_path"])
            first_bytes = first_store.read_bytes()
            first_store.write_bytes(second_store.read_bytes())
            with self.assertRaises(InvalidTag):
                manager.restore(first["id"], str(root / "wrong.txt"))
            first_store.write_bytes(first_bytes)

    def test_media_revert_alerts_are_grouped_but_events_can_continue(self):
        guard = CameraMicGuard(WindowsPrivacyAdapter(), AccessGateway(), lambda _kind: True, lambda _event: None)
        first_alert, first_count = guard._revert_alert_decision("camera", 100.0)
        second_alert, second_count = guard._revert_alert_decision("camera", 101.0)
        grouped_alert, grouped_count = guard._revert_alert_decision("camera", 110.0)
        self.assertTrue(first_alert)
        self.assertEqual(first_count, 1)
        self.assertFalse(second_alert)
        self.assertEqual(second_count, 1)
        self.assertTrue(grouped_alert)
        self.assertEqual(grouped_count, 2)

    def test_intrusion_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crypto = AppCrypto(root)
            chain_path = root / "logs" / "intrusion_chain.log"
            chain = IntrusionChain(chain_path, crypto)
            chain.append("audit", {"action": "test"})
            self.assertTrue(chain.verify()["valid"])
            chain_path.write_text(chain_path.read_text(encoding="utf-8").replace('"sequence":1', '"sequence":2'), encoding="utf-8")
            self.assertFalse(chain.verify()["valid"])

    def test_incident_report_is_encrypted_and_contains_timeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "filesentry.db")
            database.record_event({"event_type": "created", "path": "C:/evidence.txt"})
            database.record_alert("warning", "Test indicator", "Review this event", "C:/evidence.txt")
            database.record_audit("test_report", {"username": "admin"})
            destination = root / "incident.fsreport"
            result = IncidentReportBuilder(database).export_encrypted(destination, hours=24)
            self.assertEqual(result["report_version"], 1)
            self.assertTrue(destination.read_text(encoding="utf-8").startswith("FS1:"))
            report, encrypted = database.crypto.read_json(destination)
            self.assertTrue(encrypted)
            self.assertEqual(report["evidence"]["events_count"], 1)
            self.assertEqual(report["evidence"]["alerts_count"], 1)
            self.assertEqual(report["evidence"]["audits_count"], 1)


if __name__ == "__main__":
    unittest.main()
