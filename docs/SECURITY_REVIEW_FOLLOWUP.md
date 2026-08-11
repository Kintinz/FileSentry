# Security review follow-up

This document records the implementation response to the design-level review
provided for FileSentry.

## Addressed in the current workspace

- Authentication still uses PBKDF2-HMAC-SHA256 with `hmac.compare_digest`.
  Failed-attempt metadata is now persisted inside the encrypted auth record,
  so restarting the process does not immediately reset the lockout state.
- The 15-minute UI session uses `time.monotonic()` and does not retain the
  password. High-risk actions continue to request fresh authentication.
- Access grants are protected by an `RLock`, use monotonic expiry internally,
  and are keyed by the exact resource name. A Camera token cannot authorize
  Microphone or Vault operations.
- Camera/Microphone polling is documented as a minimum two-second
  watch-and-revert window. Enforcement failures generate an explicit warning;
  they are not treated as a successful lock. Every revert remains an event,
  while visible alerts are grouped to reduce alert fatigue.
- Vault ciphertext generates a fresh random nonce per encrypted chunk and uses
  AAD containing the `vault:<item_id>` purpose. Swapping two stored
  ciphertexts fails AEAD validation. Restore decrypts to a temporary file,
  checks the SHA-256 hash, and then moves it to a non-overwriting destination.
- Quarantine and Vault manifests are written using the authenticated encrypted
  JSON format. The JSON filename is part of the AEAD purpose, so moving an
  encrypted manifest to another manifest name fails authentication.
- Signed update verification supports Ed25519 signature validation, SemVer
  monotonicity, artifact hashing and symlink rejection.
- The IPC primitive has one-time challenges, client binding, HMAC validation,
  replay rejection and request-size bounds.

## Still intentionally deferred

- The hash-chain genesis fingerprint is local. An external or separately
  permissioned anchor is not enabled, so deletion of the complete local data
  directory remains outside the application's protection boundary.
- Append uses flush/fsync and startup verification. A torn final record is
  fail-closed as an integrity error; the implementation does not yet claim to
  distinguish a crash tear from deliberate tampering.
- Update revocation lists, expiry/revocation timestamps and public-key
  rotation are not yet part of the release verifier.
- A counter-based nonce format has not been introduced. The current format
  uses fresh random 96-bit nonces; changing to a counter would require a
  versioned file format and migration tests.
- The Named Pipe transport, local-only flag, Windows peer-SID validation and
  rate limiting are now implemented and integration-tested. Service-side
  password proof, 15-minute sessions and capability checks are implemented;
  audit ownership and complete mutation coverage are still pending.
- Service DPAPI/data profile migration is now implemented as an explicit,
  non-destructive staging migration. The current GUI profile remains
  user-scoped; the GUI has not yet been converted into a thin client.

## Recommended next order

1. Move the remaining sensitive operations behind the service boundary and
   make the UI a thin client.
2. Add service-owned audit emission and lifecycle recovery tests in a VM.
3. Add ETW process-to-file-to-network correlation.
4. Reassess whether a signed Minifilter is still needed before starting driver
   work.
