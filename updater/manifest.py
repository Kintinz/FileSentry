"""Verify signed FileSentry update manifests before any installer action."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from core.security import reject_symlink


MANIFEST_VERSION = 1
PUBLISHER = "FileSentry"
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def canonical_manifest(manifest: dict) -> bytes:
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_key(value: bytes | str, expected_length: int) -> bytes:
    if isinstance(value, str):
        value = value.strip()
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception:
            try:
                decoded = bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError("Khóa update không hợp lệ.") from exc
    else:
        decoded = bytes(value)
    if len(decoded) != expected_length:
        raise ValueError("Độ dài khóa update không hợp lệ.")
    return decoded


def sign_manifest(manifest: dict, private_key: bytes | str) -> dict:
    """Release-tool helper; private keys must never ship in the application."""

    key = Ed25519PrivateKey.from_private_bytes(_decode_key(private_key, 32))
    signed = dict(manifest)
    signed["signature"] = base64.b64encode(key.sign(canonical_manifest(manifest))).decode("ascii")
    return signed


def _parse_version(version: str) -> tuple[int, int, int]:
    match = _SEMVER.fullmatch(str(version))
    if not match:
        raise ValueError("Version update phải theo Semantic Versioning X.Y.Z.")
    return tuple(int(part) for part in match.groups())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_manifest(manifest: dict, artifact: str | Path, public_key: bytes | str, current_version: str | None = None) -> dict:
    if not isinstance(manifest, dict) or manifest.get("manifest_version") != MANIFEST_VERSION:
        raise ValueError("Manifest update không được hỗ trợ.")
    if manifest.get("publisher") != PUBLISHER:
        raise ValueError("Publisher update không đúng.")
    signature = manifest.get("signature")
    if not isinstance(signature, str):
        raise ValueError("Manifest thiếu chữ ký.")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise ValueError("Chữ ký manifest không hợp lệ.") from exc
    if len(signature_bytes) != 64:
        raise ValueError("Độ dài chữ ký manifest không hợp lệ.")
    verifier = Ed25519PublicKey.from_public_bytes(_decode_key(public_key, 32))
    try:
        verifier.verify(signature_bytes, canonical_manifest(manifest))
    except InvalidSignature as exc:
        raise ValueError("Chữ ký manifest không xác thực được.") from exc

    version = str(manifest.get("version", ""))
    parsed_version = _parse_version(version)
    if current_version is not None and parsed_version <= _parse_version(current_version):
        raise ValueError("Bản update không phải version mới hơn bản đang chạy.")
    artifact_path = reject_symlink(Path(artifact).expanduser(), "Artifact update không được là symbolic link.")
    if not artifact_path.is_file():
        raise FileNotFoundError("Không tìm thấy artifact update.")
    expected_hash = str(manifest.get("artifact_sha256", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("Manifest thiếu SHA-256 artifact hợp lệ.")
    actual_hash = _sha256(artifact_path)
    if actual_hash != expected_hash:
        raise ValueError("SHA-256 artifact không khớp manifest.")
    return {"valid": True, "version": version, "artifact": str(artifact_path), "sha256": actual_hash}
