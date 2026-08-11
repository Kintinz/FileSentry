# FileSentry — Implementation status

This document is the current comparison between the project plan and the code in this workspace.

## Implemented in the current V1 build

| Plan area | Status | Evidence |
|---|---|---|
| Authentication and first-run admin | Done | `core/auth.py`, `gui/app.py` |
| Password gate for sensitive UI actions | Done | `PasswordGate` and protected action wrapper |
| 15-minute in-memory authentication session | Done | `core/auth_session.py`; sensitive actions can force fresh authentication |
| Include/exclude protected areas | Done | `core/settings.py`, `core/monitor.py` |
| Dedicated protected storage area | Done at application layer | `core/settings.py`, `core/controller.py`, `gui/app.py`; creates a separate folder, registers it as an include path, opens it after authentication, and removes only management metadata without deleting the folder |
| Folder Lock ACL with encrypted original DACL backup | Done on Windows ACL boundary | `core/folder_lock.py`, `core/controller.py`, scope page; backup-before-deny, exact restore, integrity verification |
| Protection ON/OFF, timed pause, protected-area lock | Done at application layer | `core/controller.py` |
| Watchdog file monitoring and polling fallback | Done | `core/monitor.py` |
| Burst/ransomware behavior indicators | Done as detection/alerting | `core/controller.py` |
| SHA-256, double-extension and local file signals | Done | `core/file_signals.py` |
| Encrypted quarantine and restore | Done | `core/quarantine.py` |
| Encrypted per-file vault | Done in this iteration | `core/vault.py`, `gui/app.py` |
| Media Library for image/video/audio inventory | Done at application layer | `core/media_library.py`, `gui/app.py`; encrypted inventory, whole-machine local-drive sync, add/update/missing detection, policy metadata, in-app image preview, default-app opening for external video/audio, and inventory-only clear that preserves real files |
| Media delete protection | Done with Windows ACL boundary | `core/media_protection.py`; per-file delete deny, fail-closed validation |
| Media no-export mode | Done through encrypted private vault | `core/controller.py`, `core/vault.py`; moves the original into encrypted storage and removes the normal external copy after confirmation |
| Camera and microphone policy control | Done with Windows policy limitations | `core/media_guard.py` |
| Local network socket inventory and indicators | Done, local-only | `core/network_monitor.py` |
| Local double-extortion correlation | Done as a conservative local signal | `core/event_correlation.py`, `core/controller.py`, Activity/Network pages; correlates destructive or double-extension file activity with external/risky network evidence in a bounded window, records a fingerprinted evidence event and throttled alert |
| Registry/Startup/Scheduled Task/Service persistence inventory | Done, read-only | `core/persistence_monitor.py` |
| Antivirus/EDR posture check | Done, local best-effort | `core/system_health.py` |
| Encrypted append-only intrusion hash-chain | Done in this iteration | `core/intrusion_log.py`, `core/db.py` |
| Encrypted incident report export | Done in this iteration | `core/incident_report.py`, Activity page |
| App-gated Access Center | Done for Camera/Mic watch-and-revert and Vault file operations | `core/access_gateway.py`, `core/camera_mic_guard.py`, `core/vault.py`, Access Center page |
| Encrypted version metadata | Done in this iteration | `core/versioning.py`, `data/version.json` |
| Interactive guided tours anchored to real controls; click-gated action steps and read-only confirmations | Done | `gui/guides.py`, `gui/app.py` |
| Unified Protection Journey across scope, policy, monitoring and recovery | Done | `gui/app.py`; shared workflow bar, dashboard next-safe-action board and Access Center resource hub |
| Context menu theo từng màn hình và bảng dữ liệu | Done | `gui/app.py`; menu chuột phải chung cho làm mới/hướng dẫn và menu theo ngữ cảnh cho Media, Vault, Quarantine, Scope, Network, Persistence và Activity |
| Packaged EXE and self-uninstall workflow | Done with confirmation and Folder Lock preflight | `build.ps1`, `core/uninstall.py`, `gui/app.py`; all locks must unlock and verify before cleanup is scheduled |
| Review hardening: durable encrypted login lockout | Done | `core/auth.py`; failed-attempt metadata is persisted inside the encrypted auth record |
| Review hardening: monotonic access grants | Done | `core/access_gateway.py`; resource-bound token checks and monotonic expiry |
| Review hardening: media alert throttling | Done | `core/camera_mic_guard.py`, `core/controller.py`; every revert remains an event, visible alerts are grouped |
| Review hardening: Vault identity binding test | Done | `core/vault.py`, `tests/test_core.py`; Vault purpose/AAD binds ciphertext to item id |
| Product identity and application icon | Done | `core/branding.py`, `assets/filesentry-sentinel.svg`, `assets/filesentry-sentinel.ico`, `build.ps1` |
| Professional UX/UI notification layer | Done | `gui/design_system.py`, `gui/app.py`, `gui/guides.py`; toast stack, status pills, themed dialogs, hover states, spotlight overlay and chat-bubble guided tours |
| Media preview, inventory-only clear, and scrollable lists | Done at application layer | `gui/app.py`; in-memory image preview, external video/audio open, clear-without-deleting action, and vertical/horizontal scrollbars for every inventory Treeview and image preview |

## Partial or intentionally limited

- The vault keeps the original file and creates an encrypted copy. It is not a real-time Explorer lock.
- Media files kept as normal external files cannot be protected against every copy/upload path from every application. Strong no-export mode requires moving the original into the encrypted private vault; Windows Administrator/SYSTEM and kernel-level tools remain outside the user-mode trust boundary.
- Folder Lock is an NTFS ACL boundary, not encryption. It requires Windows Administrator for reliable ACL changes; Administrator/SYSTEM or Windows ownership-recovery tools remain outside the app trust boundary. Integrity mismatches are reported and are not auto-repaired.
- Whole-machine media synchronization scans mounted local drives from **ĐỒNG BỘ TOÀN BỘ MÁY**, excludes OS/application/cache directories, and retains records marked **ĐÃ RỜI KHỎI MÁY**. After the first scan, a watchdog event watcher updates media changes while the app is running; a newly mounted drive still requires another full sync.
- File monitoring observes changes after the operating system reports them; it does not attribute every event to a process.
- Network Guard reads the local socket table. It does not block connections, scan ports, resolve DNS, or upload telemetry.
- Double-extortion correlation is a local, explainable indicator only. It links time-bounded file and network observations but does not prove intrusion, identify the responsible process for every file event, or replace ETW/Sysmon correlation.
- Media Guard applies Windows privacy policy and desktop-app policy where Windows exposes them. A browser origin allowlist is stored for a future browser extension; it is not URL enforcement inside a browser yet.
- The intrusion chain detects modification, reordering, and appended records. It cannot prevent a user with control of the running account or local Administrator/SYSTEM from deleting the whole log.
- Persistence inventory does not yet cover every COM/WMI persistence surface; those require a separate, carefully scoped collector.
- The AV/EDR view reports local Windows/Defender/SecurityCenter state; it is not an antivirus engine or EDR replacement.
- Incident reports are encrypted FileSentry JSON (`.fsreport`), not PDF yet.
- Access Center uses a memory-only unlock session (default 30 minutes). Camera/Mic enforcement is watch-and-revert with a minimum 2-second polling delay, not an operating-system pre-hook. Every revert is logged; visible alerts are throttled/grouped to reduce alert fatigue. Vault import/restore now require an active `vault` session when constructed by the application controller.
- The production brand is now **FileSentry Sentinel**. Existing `FileSentry` data folders and service profile paths remain supported for compatibility.

## Not implemented / deferred to V2 or Advanced

These items are not represented as complete features in the current binary:

- Filesystem Minifilter/driver, WHQL signing, and guaranteed system-wide file blocking.
- ETW/Sysmon process-to-file-to-network correlation and kernel-level attribution.
- Signed updater with manifest verification and rollback.
- External backup/restore and scheduled backup validation.
- VirusTotal, WHOIS, GeoIP, reverse DNS and other external intelligence. These must remain explicit opt-in because they disclose indicators outside the machine.
- PDF report generation.
- Browser extension/native messaging for per-website camera/microphone enforcement.
- Full vault mount/unmount or a virtual drive. V1 remains per-file encrypted storage.
- ML classification, multi-device management and mobile clients.

## V2 groundwork implemented in this workspace

| V2 area | Status | Evidence / boundary |
|---|---|---|
| Signed update manifest verification | Done as an offline verifier | `updater/manifest.py`; Ed25519 signature, SemVer monotonicity, artifact SHA-256 and symlink rejection. It does not download or install anything. |
| Authenticated IPC protocol primitive | Done as a transport-neutral primitive | `service/ipc_protocol.py`; one-time nonce, client binding, HMAC and request-size limit. Windows Named Pipe ACL/token validation is still required. |
| Headless agent host | Experimental boundary only | `service/agent_host.py`; lifecycle wrapper around the existing controller. It is not yet a production SYSTEM service. |
| Windows service wrapper | Guarded wrapper, not rollout-ready | `service/windows_service.py`; requires provisioned IPC material and allowed user SID, and exposes only the fail-closed runtime. |
| Service-owned machine-scope data profile | Implemented with explicit migration | `service/data_profile.py`; migration is non-destructive, creates a backup, stages output, rejects unknown files and applies service ACL before publish. |
| Local-only Named Pipe transport | Implemented and integration-tested | `service/named_pipe.py`; SDDL ACL, `PIPE_REJECT_REMOTE_CLIENTS`, peer SID check, bounded message, nonce/HMAC and rate limit. |
| Fail-closed agent runtime | Implemented for read-only status and bounded mutations | `service/agent_runtime.py`; safe policy mutations require a resource-bound capability, while unsupported mutations remain rejected. |
| Explicit IPC secret provisioning | Implemented | `service/ipc_material.py`; machine-scope encrypted secret, no implicit service-side creation. |
| Service-side password proof and 15-minute session | Primitive implemented, UI integration pending | `service/auth_broker.py`, `core/auth.py`; password is proven without sending plaintext, session/capability material remains memory-only. |
| Capability-bound mutation handlers | Partial, fail-closed by default | `service/agent_runtime.py`; protection, pause, scope, media mode and Vault-session handlers require a matching resource capability. Quarantine, uninstall and other unsupported mutations remain rejected. |
| Thin GUI client over Named Pipe | Client helper implemented; GUI integration pending | `service/client.py`; password-proof and capability calls are available, but the current GUI still uses the local controller directly. |
| Service lifecycle install/recovery | Not complete | Windows service wrapper is guarded and configured explicitly; installer, recovery policy and rollback are not yet production-ready. |

The V2 service split is intentionally not presented as complete. The profile, transport, read-only runtime and service-side authentication primitive now exist, but the thin-client transport integration, capability-bound mutation handlers and service lifecycle installation/recovery are still required before production rollout.

The implementation deliberately reports these as deferred instead of presenting a UI-only placeholder as kernel, service, or network enforcement.
