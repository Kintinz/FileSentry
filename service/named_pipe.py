"""Local-only Windows Named Pipe transport for the V2 agent boundary."""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable

from .ipc_protocol import IpcAuthenticator, MAX_MESSAGE_BYTES


class NamedPipeUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class NamedPipeConfig:
    name: str = r"\\.\pipe\FileSentryAgent.v1"
    max_message_bytes: int = MAX_MESSAGE_BYTES
    max_requests_per_minute: int = 60


def current_user_sid() -> str:
    if __import__("sys").platform != "win32":
        raise NamedPipeUnavailable("Named Pipe chỉ hỗ trợ trên Windows.")
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return win32security.ConvertSidToStringSid(sid)
    finally:
        token.Close()


def _security_attributes(allowed_sid: str):
    import pywintypes
    import win32security

    if not allowed_sid or ";" in allowed_sid or "(" in allowed_sid:
        raise ValueError("Allowed SID không hợp lệ.")
    sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;{allowed_sid})"
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, win32security.SDDL_REVISION_1)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


class NamedPipeServer:
    """Authenticated, bounded, local-only request server.

    The handler is called only after the OS peer SID, one-time challenge and
    HMAC have all passed. Passwords must never be placed in the request.
    """

    def __init__(
        self,
        shared_secret: bytes,
        allowed_sid: str,
        handler: Callable[[str, dict], dict],
        config: NamedPipeConfig | None = None,
    ):
        self.config = config or NamedPipeConfig()
        if len(shared_secret) < 32:
            raise ValueError("IPC secret phải có ít nhất 32 bytes.")
        self.allowed_sid = str(allowed_sid)
        self.authenticator = IpcAuthenticator(shared_secret)
        self.handler = handler
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.startup_error: Exception | None = None
        self.thread: threading.Thread | None = None
        self._rate_lock = threading.Lock()
        self._request_times: dict[str, deque[float]] = defaultdict(deque)

    def start(self) -> None:
        if __import__("sys").platform != "win32":
            raise NamedPipeUnavailable("Named Pipe chỉ hỗ trợ trên Windows.")
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.ready_event.clear()
        self.startup_error = None
        self.thread = threading.Thread(target=self._run, name="FileSentryNamedPipe", daemon=True)
        self.thread.start()
        if not self.ready_event.wait(5):
            self.stop()
            raise NamedPipeUnavailable("Named Pipe không khởi động được trong thời hạn an toàn.") from self.startup_error

    def stop(self) -> None:
        self.stop_event.set()
        self._poke()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        self.thread = None

    def _create_pipe(self):
        import win32pipe

        reject_remote = getattr(win32pipe, "PIPE_REJECT_REMOTE_CLIENTS", 0x8)
        open_mode = win32pipe.PIPE_ACCESS_DUPLEX
        pipe_mode = win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT | reject_remote
        return win32pipe.CreateNamedPipe(
            self.config.name,
            open_mode,
            pipe_mode,
            1,
            self.config.max_message_bytes,
            self.config.max_message_bytes,
            1000,
            _security_attributes(self.allowed_sid),
        )

    def _run(self) -> None:
        import pywintypes
        import win32file
        import win32pipe

        while not self.stop_event.is_set():
            pipe = None
            try:
                pipe = self._create_pipe()
                self.ready_event.set()
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except pywintypes.error as exc:
                    if getattr(exc, "winerror", None) != 535:
                        raise
                if self.stop_event.is_set():
                    break
                self._serve_connection(pipe)
            except (OSError, pywintypes.error) as exc:
                if not self.ready_event.is_set():
                    self.startup_error = exc
                    self.stop_event.set()
                    return
                if not self.stop_event.is_set():
                    time.sleep(0.1)
            finally:
                if pipe is not None:
                    try:
                        win32pipe.DisconnectNamedPipe(pipe)
                    except Exception:
                        pass
                    try:
                        win32file.CloseHandle(pipe)
                    except Exception:
                        pass

    def _validate_peer(self, pipe) -> bool:
        import win32api
        import win32con
        import win32security

        try:
            win32security.ImpersonateNamedPipeClient(pipe)
            token = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
            try:
                sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
                peer_sid = win32security.ConvertSidToStringSid(sid)
            finally:
                token.Close()
            return peer_sid == self.allowed_sid
        except Exception:
            return False
        finally:
            try:
                win32security.RevertToSelf()
            except Exception:
                pass

    def _serve_connection(self, pipe) -> None:
        first_payload = self._read(pipe)
        if first_payload is None:
            return
        if not self._validate_peer(pipe):
            self._write(pipe, {"ok": False, "error": "peer_rejected"})
            return
        self._write(pipe, self._dispatch(first_payload))
        while not self.stop_event.is_set():
            payload = self._read(pipe)
            if payload is None:
                return
            response = self._dispatch(payload)
            self._write(pipe, response)

    def _dispatch(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            return {"ok": False, "error": "invalid_message"}
        client_id = str(payload.get("client_id", ""))
        if not client_id or not self._allow_request(client_id):
            return {"ok": False, "error": "rate_limited" if client_id else "invalid_client"}
        operation = payload.get("op")
        if operation == "challenge":
            return {"ok": True, "challenge": self.authenticator.issue_challenge(client_id)}
        if operation != "request":
            return {"ok": False, "error": "unsupported_operation"}
        challenge = payload.get("challenge")
        request = payload.get("request")
        mac = payload.get("mac")
        if not isinstance(challenge, dict) or not isinstance(request, dict) or not isinstance(mac, str):
            return {"ok": False, "error": "invalid_envelope"}
        if not self.authenticator.authenticate(client_id, challenge, request, mac):
            return {"ok": False, "error": "authentication_failed"}
        try:
            result = self.handler(client_id, request)
            return {"ok": True, "result": result if isinstance(result, dict) else {"value": result}}
        except Exception:
            return {"ok": False, "error": "handler_failed"}

    def _allow_request(self, client_id: str) -> bool:
        now = time.monotonic()
        with self._rate_lock:
            timestamps = self._request_times[client_id]
            while timestamps and timestamps[0] <= now - 60.0:
                timestamps.popleft()
            if len(timestamps) >= self.config.max_requests_per_minute:
                return False
            timestamps.append(now)
            return True

    def _read(self, pipe) -> dict | None:
        import pywintypes
        import win32file

        try:
            _result, raw = win32file.ReadFile(pipe, self.config.max_message_bytes + 1)
        except pywintypes.error as exc:
            if getattr(exc, "winerror", None) in {109, 232, 234}:
                return None
            raise
        if len(raw) > self.config.max_message_bytes:
            return {"op": "invalid", "error": "message_too_large"}
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"op": "invalid", "error": "invalid_json"}
        return value

    @staticmethod
    def _write(pipe, payload: dict) -> None:
        import win32file

        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        win32file.WriteFile(pipe, raw)

    def _poke(self) -> None:
        if __import__("sys").platform != "win32":
            return
        import pywintypes
        import win32con
        import win32file

        try:
            handle = win32file.CreateFile(self.config.name, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None, win32con.OPEN_EXISTING, 0, None)
            win32file.CloseHandle(handle)
        except pywintypes.error:
            pass


class NamedPipeClient:
    def __init__(self, shared_secret: bytes, client_id: str, config: NamedPipeConfig | None = None):
        if __import__("sys").platform != "win32":
            raise NamedPipeUnavailable("Named Pipe chỉ hỗ trợ trên Windows.")
        self.config = config or NamedPipeConfig()
        self.client_id = str(client_id)
        self.authenticator = IpcAuthenticator(shared_secret)

    def request(self, request: dict) -> dict:
        import pywintypes
        import win32con
        import win32file

        handle = self._open_handle()
        try:
            win32pipe = __import__("win32pipe")
            win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
            self._write(handle, {"op": "challenge", "client_id": self.client_id})
            challenge_response = self._read(handle)
            if not challenge_response.get("ok"):
                return challenge_response
            challenge = challenge_response["challenge"]
            mac = self.authenticator.sign_request(self.client_id, challenge, request)
            self._write(handle, {"op": "request", "client_id": self.client_id, "challenge": challenge, "request": request, "mac": mac})
            return self._read(handle)
        except pywintypes.error as exc:
            raise NamedPipeUnavailable("Không thể giao tiếp với FileSentry Agent Named Pipe.") from exc
        finally:
            win32file.CloseHandle(handle)

    def _open_handle(self):
        import pywintypes
        import win32con
        import win32file
        import win32pipe

        deadline = time.monotonic() + 5.0
        while True:
            try:
                win32pipe.WaitNamedPipe(self.config.name, 1000)
                return win32file.CreateFile(self.config.name, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None, win32con.OPEN_EXISTING, 0, None)
            except pywintypes.error as exc:
                if getattr(exc, "winerror", None) not in {2, 231} or time.monotonic() >= deadline:
                    raise NamedPipeUnavailable("Không thể mở FileSentry Agent Named Pipe.") from exc
                time.sleep(0.05)

    def _read(self, handle) -> dict:
        import win32file

        _result, raw = win32file.ReadFile(handle, self.config.max_message_bytes + 1)
        if len(raw) > self.config.max_message_bytes:
            raise NamedPipeUnavailable("Response IPC quá lớn.")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise NamedPipeUnavailable("Response IPC không hợp lệ.")
        return value

    @staticmethod
    def _write(handle, payload: dict) -> None:
        import win32file

        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("IPC request quá lớn.")
        win32file.WriteFile(handle, raw)
