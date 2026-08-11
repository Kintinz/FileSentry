"""Authenticated encryption for FileSentry data at rest.

The application data key is wrapped by Windows DPAPI and the payloads are
encrypted with AES-GCM. This protects data if the data directory is copied or
read offline. A local Administrator can still access a running user's DPAPI
context; that is an OS trust boundary, not something an app can remove.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .security import atomic_write_bytes, ensure_private_directory, ensure_private_file, reject_symlink


MAGIC = b"FSQ1"
CHUNK_SIZE = 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
PREFIX = "FS1:"
CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes):
    buffer = ctypes.create_string_buffer(data)
    pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    return _DataBlob(len(data), pointer), buffer


def _dpapi_protect(data: bytes, scope: str = "user") -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("FileSentry secure storage requires Windows DPAPI.")
    if scope not in {"user", "machine"}:
        raise ValueError("DPAPI scope must be 'user' or 'machine'.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    input_blob, input_buffer = _blob(data)
    output_blob = _DataBlob()
    flags = CRYPTPROTECT_UI_FORBIDDEN | (CRYPTPROTECT_LOCAL_MACHINE if scope == "machine" else 0)
    ok = crypt32.CryptProtectData(
        ctypes.byref(input_blob), None, None, None, None,
        flags, ctypes.byref(output_blob)
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


def _dpapi_unprotect(data: bytes, scope: str = "user") -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("FileSentry secure storage requires Windows DPAPI.")
    if scope not in {"user", "machine"}:
        raise ValueError("DPAPI scope must be 'user' or 'machine'.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    input_blob, input_buffer = _blob(data)
    output_blob = _DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(input_blob), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output_blob)
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


class AppCrypto:
    def __init__(self, root: Path, dpapi_scope: str = "user"):
        self.root = Path(root)
        if dpapi_scope not in {"user", "machine"}:
            raise ValueError("DPAPI scope must be 'user' or 'machine'.")
        self.dpapi_scope = dpapi_scope
        ensure_private_directory(self.root)
        self.key_path = self.root / "app_key.dpapi"
        self.key = self._load_or_create_key()
        if len(self.key) != 32:
            raise ValueError("Khóa dữ liệu FileSentry không hợp lệ.")
        self.aead = AESGCM(self.key)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            reject_symlink(self.key_path, "Khóa dữ liệu không được là symbolic link.")
            key = _dpapi_unprotect(self.key_path.read_bytes(), self.dpapi_scope)
            ensure_private_file(self.key_path)
            return key
        key = AESGCM.generate_key(bit_length=256)
        protected = _dpapi_protect(key, self.dpapi_scope)
        atomic_write_bytes(self.key_path, protected)
        return key

    @staticmethod
    def is_encrypted(value: str) -> bool:
        return isinstance(value, str) and value.startswith(PREFIX)

    def encrypt_text(self, value: str, purpose: str = "") -> str:
        nonce = os.urandom(12)
        ciphertext = self.aead.encrypt(nonce, value.encode("utf-8"), purpose.encode("utf-8"))
        return PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt_text(self, value: str, purpose: str = "") -> str:
        if not self.is_encrypted(value):
            return value
        try:
            raw = base64.urlsafe_b64decode(value[len(PREFIX):].encode("ascii"))
            return self.aead.decrypt(raw[:12], raw[12:], purpose.encode("utf-8")).decode("utf-8")
        except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Dữ liệu FileSentry bị hỏng hoặc không đúng khóa mã hóa.") from exc

    def write_json(self, path: Path, payload: dict) -> None:
        encoded = self.encrypt_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), f"json:{path.name}")
        atomic_write_bytes(path, encoded.encode("utf-8"))

    def read_json(self, path: Path) -> tuple[dict, bool]:
        reject_symlink(path, "Không đọc cấu hình từ symbolic link.")
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ValueError("Dữ liệu cấu hình vượt giới hạn an toàn.")
        raw = path.read_text(encoding="utf-8")
        encrypted = self.is_encrypted(raw)
        decoded = self.decrypt_text(raw, f"json:{path.name}") if encrypted else raw
        return json.loads(decoded), encrypted

    def encrypt_file(self, source: Path, destination: Path, purpose: str) -> None:
        reject_symlink(source, "Không mã hóa file nguồn là symbolic link.")
        reject_symlink(destination, "Không ghi file mã hóa qua symbolic link.")
        with source.open("rb") as input_file, destination.open("wb") as output_file:
            output_file.write(MAGIC)
            index = 0
            while True:
                chunk = input_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                nonce = os.urandom(12)
                aad = f"{purpose}:{index}".encode("utf-8")
                ciphertext = self.aead.encrypt(nonce, chunk, aad)
                output_file.write(struct.pack(">I", len(ciphertext)))
                output_file.write(nonce)
                output_file.write(ciphertext)
                index += 1

    def decrypt_file(self, source: Path, destination: Path, purpose: str) -> None:
        with source.open("rb") as input_file, destination.open("wb") as output_file:
            if input_file.read(4) != MAGIC:
                raise ValueError("File quarantine không có định dạng mã hóa FileSentry.")
            index = 0
            while True:
                size_bytes = input_file.read(4)
                if not size_bytes:
                    break
                if len(size_bytes) != 4:
                    raise ValueError("File quarantine bị thiếu dữ liệu.")
                size = struct.unpack(">I", size_bytes)[0]
                if size < 16 or size > CHUNK_SIZE + 16:
                    raise ValueError("Kích thước chunk quarantine không hợp lệ.")
                nonce = input_file.read(12)
                ciphertext = input_file.read(size)
                if len(nonce) != 12 or len(ciphertext) != size:
                    raise ValueError("File quarantine bị thiếu chunk.")
                aad = f"{purpose}:{index}".encode("utf-8")
                output_file.write(self.aead.decrypt(nonce, ciphertext, aad))
                index += 1
