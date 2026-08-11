# FileSentry V2 agent boundary

This directory contains the V2 service boundary and its safe foundations:

- `ipc_protocol.py` defines a transport-neutral one-time challenge/HMAC
  envelope with client binding and a request-size limit.
- `data_profile.py` creates a separate machine-scope DPAPI profile and provides
  a non-destructive V1 migration with backup, staging and rollback-on-error.
- `named_pipe.py` provides a local-only message pipe with explicit SDDL ACL,
  `PIPE_REJECT_REMOTE_CLIENTS`, peer SID validation, nonce/HMAC authentication,
  bounded messages and request rate limiting.
- `auth_broker.py` owns a memory-only password-proof challenge, 15-minute
  service session and short-lived resource capabilities. Plaintext passwords
  never cross the IPC boundary.
- `client.py` is the thin-client helper for UI/tray code. It keeps only the
  service session token and obtains a fresh resource capability per protected
  operation; it never stores the plaintext password.
- `agent_runtime.py` runs the controller against the service profile, exposes
  read-only status actions, and accepts the authentication/capability protocol.
  State-changing handlers remain fail-closed until each one is capability-bound.
- `windows_service.py` is an explicitly configured pywin32 wrapper. It fails
  closed when the allowed interactive SID or provisioned IPC secret is missing.
- `ipc_material.py` provisions the IPC secret explicitly; SYSTEM never creates
  a new secret after a failed or incomplete provisioning.

The current **FileSentry Sentinel** GUI remains the supported executable. The service wrapper requires
an explicit IPC provisioning step and an allowed interactive-user SID. The
current service runtime intentionally exposes read-only operations; policy
changes still fail closed until capability-bound mutation handlers and the
thin-client UI integration are complete.
