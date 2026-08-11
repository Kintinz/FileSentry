"""Optional pywin32 service wrapper for V2 agent experimentation.

It is deliberately not wired into the normal EXE. Running it requires the
same-user data profile or a separately designed service-owned IPC/data profile.
"""

from __future__ import annotations

import os
import sys


if sys.platform == "win32":  # pragma: no cover - requires SCM interaction
    try:
        import win32event
        import win32service
        import win32serviceutil
    except ImportError:
        FileSentryAgentService = None
    else:
        from .agent_runtime import AgentRuntime
        from .ipc_material import IpcSecretStore

        class FileSentryAgentService(win32serviceutil.ServiceFramework):
            _svc_name_ = "FileSentryAgent"
            _svc_display_name_ = "FileSentry Agent"
            _svc_description_ = "FileSentry headless local defensive monitoring agent."

            def __init__(self, args):
                super().__init__(args)
                self.stop_handle = win32event.CreateEvent(None, 0, 0, None)
                self.runtime = None

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                if self.runtime is not None:
                    self.runtime.stop()
                win32event.SetEvent(self.stop_handle)

            def SvcDoRun(self):
                allowed_sid = os.environ.get("FILESENTRY_AGENT_ALLOWED_SID", "")
                if not allowed_sid.startswith("S-"):
                    raise RuntimeError("FileSentryAgent thiếu FILESENTRY_AGENT_ALLOWED_SID; fail-closed.")
                secret = IpcSecretStore().load()
                data_root = os.environ.get("FILESENTRY_SERVICE_DATA_DIR")
                pipe_name = os.environ.get("FILESENTRY_AGENT_PIPE", r"\\.\pipe\FileSentryAgent.v1")
                self.runtime = AgentRuntime(data_root, allowed_sid, secret, pipe_name)
                self.runtime.start()
                win32event.WaitForSingleObject(self.stop_handle, win32event.INFINITE)

else:
    FileSentryAgentService = None
