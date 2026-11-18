"""4-Layer Native OS & Process Sandbox for Weber MCP (Windows Job Object + Audit Hook + FS Jail + Env Sanitizer)."""

from __future__ import annotations

import atexit
import os
import re
import shlex
import shutil
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from weber_mcp.security import SecurityError

try:
    import win32api
    import win32job

    _WIN32JOB_AVAILABLE = True
except ImportError:  # pragma: no cover - non-Windows fallback
    win32api = None  # type: ignore[assignment]
    win32job = None  # type: ignore[assignment]
    _WIN32JOB_AVAILABLE = False

_PROJECT_ROOT = os.path.normcase(os.path.abspath(str(Path(__file__).resolve().parent.parent)))

_ALLOWED_ENV_EXACT = frozenset({
    "COMSPEC",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PUBLIC",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "WINDIR",
    "PLAYWRIGHT_BROWSERS_PATH",
    "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD",
    "LANG",
    "LC_ALL",
})

_SECRET_ENV_PATTERNS = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE|"
    r"^AWS_|^AZURE_|^GCP_|^GOOGLE_|^OPENAI_|^ANTHROPIC_|^GITHUB_|^GH_|^DATABASE_|^SSH_)",
    re.IGNORECASE,
)

_SENSITIVE_READ_MARKERS = (
    "\\.ssh\\",
    "/.ssh/",
    "\\.aws\\",
    "/.aws/",
    "\\id_rsa",
    "/id_rsa",
    "\\id_ed25519",
    "/id_ed25519",
    "\\login data",
    "/login data",
    "\\microsoft\\credentials\\",
    "\\system32\\config\\sam",
)

_WRITE_MODES = ("w", "a", "x", "+")
_WRITE_FLAGS = (
    getattr(os, "O_WRONLY", 1)
    | getattr(os, "O_RDWR", 2)
    | getattr(os, "O_CREAT", 0x100)
    | getattr(os, "O_TRUNC", 0x200)
    | getattr(os, "O_APPEND", 0x8)
)


class SandboxViolationError(SecurityError):
    """Raised when an operation violates Weber MCP's OS/Process sandbox policy."""


@dataclass
class SandboxConfig:
    """Configuration for Weber MCP's 4-layer native OS & process sandbox."""

    max_active_processes: int = 32
    max_job_memory_mb: int = 2048
    enforce_job_object: bool = True
    enforce_ui_restrictions: bool = True
    enforce_filesystem_jail: bool = True
    enforce_audit_hook: bool = True
    enforce_env_sanitization: bool = True


def _extract_first_token(cmd_args: Any) -> tuple[str, str]:
    """Extract the invoked executable token and normalized full command string."""
    if isinstance(cmd_args, (list, tuple)):
        parts = [str(x) for x in cmd_args if x is not None]
        first = parts[0] if parts else ""
        return first, " ".join(parts)

    if isinstance(cmd_args, str):
        cmd_str = cmd_args.strip()
        if not cmd_str:
            return "", ""
        if cmd_str.startswith('"'):
            end_quote = cmd_str.find('"', 1)
            if end_quote != -1:
                return cmd_str[1:end_quote], cmd_str
        try:
            tokens = shlex.split(cmd_str, posix=(os.name != "nt"))
            first = tokens[0].strip('"') if tokens else cmd_str.split()[0]
        except ValueError:
            first = cmd_str.split()[0].strip('"')
        return first, cmd_str

    return "", ""


class WeberSandbox:
    """4-layer OS/Process Sandbox: Job Object, Filesystem Jail, Runtime Audit Hook, Env Sanitizer."""

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()
        self.activated = False
        self.job_active = False
        self.ui_restrictions_active = False
        self.job_error: str = ""
        self.audit_armed = False
        self._hook_installed = False
        self._job_handle: Any = None
        self._tls = threading.local()
        self._lock = threading.Lock()
        self._cleanup_registered = False

        self.original_temp_dir = os.path.normcase(os.path.abspath(tempfile.gettempdir()))
        self.sandbox_root = ""
        self.temp_dir = ""
        self.chromium_cache_dir = ""
        self.violations: list[dict[str, str]] = []
        self.last_stripped_env_vars: list[str] = []

    def _record_violation(self, event: str, detail: str) -> None:
        self.violations.append({"event": event, "detail": detail})
        if len(self.violations) > 50:
            self.violations = self.violations[-50:]

    def _is_inside_dir(self, target_path: str, allowed_dir: str) -> bool:
        if not target_path or not allowed_dir:
            return False
        norm_target = os.path.normcase(os.path.abspath(target_path))
        norm_allowed = os.path.normcase(os.path.abspath(allowed_dir))
        try:
            return os.path.commonpath([norm_target, norm_allowed]) == norm_allowed
        except ValueError:
            return False

    def _is_allowed_write_path(self, raw_path: str) -> bool:
        if not raw_path:
            return False
        norm_raw = raw_path.strip()
        lower_raw = norm_raw.lower()
        if lower_raw in ("nul", "con", "prn", "aux") or lower_raw.startswith("\\\\.\\pipe\\"):
            return True
        if os.devnull and lower_raw == os.devnull.lower():
            return True

        abs_path = os.path.normcase(os.path.abspath(norm_raw))

        # Allow inside the ephemeral sandbox jail
        if self.sandbox_root and self._is_inside_dir(abs_path, self.sandbox_root):
            return True

        # Allow pytest cache and project __pycache__ bytecode writes during test/import runs
        pytest_cache = os.path.join(_PROJECT_ROOT, ".pytest_cache")
        if self._is_inside_dir(abs_path, pytest_cache):
            return True
        if (
            os.path.basename(abs_path) == "__pycache__"
            or os.path.basename(os.path.dirname(abs_path)) == "__pycache__"
        ) and self._is_inside_dir(abs_path, _PROJECT_ROOT):
            return True

        return False

    def _is_sensitive_read_path(self, raw_path: str) -> bool:
        if not raw_path:
            return False
        abs_lower = os.path.normcase(os.path.abspath(raw_path)).replace("/", "\\")
        return any(marker.replace("/", "\\") in abs_lower for marker in _SENSITIVE_READ_MARKERS)

    def _is_allowed_subprocess(self, args: tuple[Any, ...]) -> tuple[bool, str]:
        executable = args[0] if len(args) > 0 else None
        cmd_args = args[1] if len(args) > 1 else None

        first_token, full_cmd = _extract_first_token(cmd_args)
        target_exe = str(executable).strip('"') if executable else first_token
        if not target_exe:
            return False, "Empty executable in subprocess.Popen"

        norm_exe = os.path.normcase(os.path.abspath(target_exe))
        norm_cmd = os.path.normcase(full_cmd)

        # Allow ONLY Playwright's bundled Node driver running cli.js
        if norm_exe.endswith("\\playwright\\driver\\node.exe") and "\\playwright\\driver\\package\\cli.js" in norm_cmd:
            return True, norm_exe

        # Allow ONLY Playwright's Chromium executable
        if norm_exe.endswith("\\chrome.exe") and "\\ms-playwright\\" in norm_exe:
            return True, norm_exe

        return False, f"executable='{target_exe}' cmd='{full_cmd[:160]}'"

    def _audit_hook(self, event: str, args: tuple[Any, ...]) -> None:
        """C-level Python runtime audit hook blocking unauthorized processes, writes, and registry edits."""
        if not self.audit_armed:
            return
        if getattr(self._tls, "in_hook", False):
            return

        self._tls.in_hook = True
        try:
            # 1. Block direct OS shell / exec / spawn calls completely
            if event in ("os.system", "os.fork", "os.forkpty") or event.startswith(
                ("os.exec", "os.spawn")
            ):
                detail = f"Blocked forbidden process execution call '{event}' with args={args[:2]!r}"
                self._record_violation(event, detail)
                raise SandboxViolationError(f"Sandbox blocked {detail}")

            # 2. Allowlist subprocess.Popen strictly to Playwright Node driver & Chromium
            if event == "subprocess.Popen":
                allowed, info = self._is_allowed_subprocess(args)
                if not allowed:
                    detail = f"Blocked unauthorized subprocess.Popen ({info})"
                    self._record_violation(event, detail)
                    raise SandboxViolationError(f"Sandbox blocked {detail}")
                return

            # 3. Inspect file open() calls for credential reads and outside-jail writes
            if event == "open" and len(args) >= 1:
                path_arg = args[0]
                if isinstance(path_arg, int):
                    return
                try:
                    raw_path = os.fsdecode(os.fspath(path_arg))
                except TypeError:
                    raw_path = str(path_arg)

                if self._is_sensitive_read_path(raw_path):
                    detail = f"Blocked read access to sensitive credential file: '{raw_path}'"
                    self._record_violation(event, detail)
                    raise SandboxViolationError(f"Sandbox blocked {detail}")

                mode_str = str(args[1] or "") if len(args) > 1 and args[1] is not None else ""
                flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
                is_write = any(ch in mode_str for ch in _WRITE_MODES) or bool(flags & _WRITE_FLAGS)

                if is_write and self.config.enforce_filesystem_jail:
                    if not self._is_allowed_write_path(raw_path):
                        detail = f"Blocked file write outside sandbox jail: '{raw_path}' (mode={mode_str!r})"
                        self._record_violation(event, detail)
                        raise SandboxViolationError(f"Sandbox blocked {detail}")
                return

            # 4. Inspect filesystem mutations outside the sandbox jail
            if event in (
                "os.remove",
                "os.unlink",
                "os.rmdir",
                "os.mkdir",
                "os.makedirs",
                "os.rename",
                "os.replace",
            ) and self.config.enforce_filesystem_jail:
                paths_to_check: list[Any] = []
                if len(args) >= 1:
                    paths_to_check.append(args[0])
                if event in ("os.rename", "os.replace") and len(args) >= 2:
                    paths_to_check.append(args[1])

                for p_arg in paths_to_check:
                    if p_arg is None or isinstance(p_arg, int):
                        continue
                    try:
                        p_str = os.fsdecode(os.fspath(p_arg))
                    except TypeError:
                        p_str = str(p_arg)
                    if not self._is_allowed_write_path(p_str):
                        detail = f"Blocked filesystem mutation '{event}' outside sandbox jail: '{p_str}'"
                        self._record_violation(event, detail)
                        raise SandboxViolationError(f"Sandbox blocked {detail}")
                return

            # 5. Block Windows Registry mutations
            if event in (
                "winreg.CreateKey",
                "winreg.DeleteKey",
                "winreg.DeleteValue",
                "winreg.SetValue",
                "winreg.SetValueEx",
                "winreg.SaveKey",
            ):
                detail = f"Blocked Windows Registry modification '{event}': {args[:2]!r}"
                self._record_violation(event, detail)
                raise SandboxViolationError(f"Sandbox blocked {detail}")
        finally:
            self._tls.in_hook = False

    def _setup_filesystem_jail(self) -> None:
        base_temp = self.original_temp_dir or tempfile.gettempdir()
        jail_name = f"weber_sandbox_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        self.sandbox_root = os.path.normcase(os.path.abspath(os.path.join(base_temp, jail_name)))
        self.temp_dir = os.path.join(self.sandbox_root, "tmp")
        self.chromium_cache_dir = os.path.join(self.sandbox_root, "chromium_cache")

        os.makedirs(self.temp_dir, exist_ok=True)
        os.makedirs(self.chromium_cache_dir, exist_ok=True)

        os.environ["TEMP"] = self.temp_dir
        os.environ["TMP"] = self.temp_dir
        os.environ["TMPDIR"] = self.temp_dir
        tempfile.tempdir = self.temp_dir

    def _setup_windows_job_object(self) -> None:
        if not self.config.enforce_job_object or not _WIN32JOB_AVAILABLE:
            return

        try:
            hjob = win32job.CreateJobObject(None, "")
            info = win32job.QueryInformationJobObject(hjob, win32job.JobObjectExtendedLimitInformation)
            info["BasicLimitInformation"]["LimitFlags"] = (
                win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | win32job.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
                | win32job.JOB_OBJECT_LIMIT_BREAKAWAY_OK
            )
            info["BasicLimitInformation"]["ActiveProcessLimit"] = self.config.max_active_processes
            info["JobMemoryLimit"] = self.config.max_job_memory_mb * 1024 * 1024
            win32job.SetInformationJobObject(hjob, win32job.JobObjectExtendedLimitInformation, info)

            if self.config.enforce_ui_restrictions:
                ui_flags = (
                    win32job.JOB_OBJECT_UILIMIT_READCLIPBOARD
                    | win32job.JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                    | win32job.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                    | win32job.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                    | win32job.JOB_OBJECT_UILIMIT_EXITWINDOWS
                    | win32job.JOB_OBJECT_UILIMIT_GLOBALATOMS
                    | win32job.JOB_OBJECT_UILIMIT_HANDLES
                )
                win32job.SetInformationJobObject(
                    hjob, win32job.JobObjectBasicUIRestrictions, {"UIRestrictionsClass": ui_flags}
                )
                self.ui_restrictions_active = True

            win32job.AssignProcessToJobObject(hjob, win32api.GetCurrentProcess())
            self._job_handle = hjob
            self.job_active = True
            self.job_error = ""
        except Exception as exc:
            self.job_active = False
            self.job_error = str(exc)

    def activate(self) -> WeberSandbox:
        """Activate all configured OS/process sandbox layers idempotently."""
        with self._lock:
            if self.activated:
                return self

            if self.config.enforce_filesystem_jail and not self.sandbox_root:
                self._setup_filesystem_jail()

            if self.config.enforce_job_object and not self.job_active:
                self._setup_windows_job_object()

            if self.config.enforce_audit_hook:
                if not self._hook_installed:
                    sys.addaudithook(self._audit_hook)
                    self._hook_installed = True
                self.audit_armed = True

            if not self._cleanup_registered:
                atexit.register(self.cleanup)
                self._cleanup_registered = True

            self.activated = True
            return self

    def get_sanitized_env(self) -> tuple[dict[str, str], list[str]]:
        """Return a stripped environment dict safe for Playwright/Chromium child processes."""
        clean_env: dict[str, str] = {}
        stripped: list[str] = []

        if not self.config.enforce_env_sanitization:
            return dict(os.environ), []

        for key, val in os.environ.items():
            upper_key = key.upper()
            if _SECRET_ENV_PATTERNS.search(upper_key):
                stripped.append(key)
                continue
            if upper_key in _ALLOWED_ENV_EXACT:
                clean_env[key] = val
            else:
                stripped.append(key)

        if self.temp_dir:
            clean_env["TEMP"] = self.temp_dir
            clean_env["TMP"] = self.temp_dir
            clean_env["TMPDIR"] = self.temp_dir

        self.last_stripped_env_vars = sorted(stripped)
        return clean_env, self.last_stripped_env_vars

    def get_job_metrics(self) -> dict[str, Any]:
        """Query live Windows Kernel Job Object accounting and memory metrics."""
        if not self.job_active or self._job_handle is None or not _WIN32JOB_AVAILABLE:
            return {"job_active": False, "error": self.job_error or "Job Object inactive"}

        try:
            acct = win32job.QueryInformationJobObject(
                self._job_handle, win32job.JobObjectBasicAccountingInformation
            )
            ext = win32job.QueryInformationJobObject(
                self._job_handle, win32job.JobObjectExtendedLimitInformation
            )
            return {
                "job_active": True,
                "active_processes": int(acct.get("ActiveProcesses", 0)),
                "total_processes": int(acct.get("TotalProcesses", 0)),
                "terminated_processes": int(acct.get("TotalTerminatedProcesses", 0)),
                "peak_job_memory_mb": round(int(ext.get("PeakJobMemoryUsed", 0)) / (1024 * 1024), 2),
                "total_user_time_ms": round(int(acct.get("TotalUserTime", 0)) / 10000.0, 2),
                "total_kernel_time_ms": round(int(acct.get("TotalKernelTime", 0)) / 10000.0, 2),
                "page_fault_count": int(acct.get("TotalPageFaultCount", 0)),
            }
        except Exception as exc:
            return {"job_active": self.job_active, "error": str(exc)}

    def get_status_dict(self) -> dict[str, Any]:
        """Return full status and live telemetry of all 4 sandbox layers."""
        _, stripped_vars = self.get_sanitized_env()
        return {
            "activated": self.activated,
            "platform": sys.platform,
            "layers": {
                "windows_job_object": {
                    "active": self.job_active,
                    "max_job_memory_mb": self.config.max_job_memory_mb,
                    "max_active_processes": self.config.max_active_processes,
                    "ui_and_clipboard_isolated": self.ui_restrictions_active,
                    "error": self.job_error or None,
                    "metrics": self.get_job_metrics(),
                },
                "filesystem_jail": {
                    "active": bool(self.sandbox_root),
                    "sandbox_root": self.sandbox_root,
                    "temp_dir": self.temp_dir,
                    "chromium_cache_dir": self.chromium_cache_dir,
                },
                "python_audit_hook": {
                    "active": self.audit_armed,
                    "blocked_violation_count": len(self.violations),
                    "recent_violations": self.violations[-10:],
                },
                "env_sanitization": {
                    "active": self.config.enforce_env_sanitization,
                    "stripped_var_count": len(stripped_vars),
                    "stripped_vars": stripped_vars,
                },
            },
        }

    def get_compact_status_dict(self) -> dict[str, Any]:
        """Return compact sandbox status omitting verbose stripped_vars list for search payloads."""
        status = self.get_status_dict()
        env_layer = status["layers"].get("env_sanitization")
        if isinstance(env_layer, dict):
            env_layer.pop("stripped_vars", None)
        return status

    def cleanup(self) -> None:
        """Remove ephemeral sandbox directory on process exit."""
        if self.sandbox_root and os.path.isdir(self.sandbox_root):
            try:
                shutil.rmtree(self.sandbox_root, ignore_errors=True)
            except Exception:
                pass


_shared_sandbox: WeberSandbox | None = None
_singleton_lock = threading.Lock()


def get_sandbox() -> WeberSandbox:
    """Return the shared WeberSandbox instance without forcing activation."""
    global _shared_sandbox
    with _singleton_lock:
        if _shared_sandbox is None:
            _shared_sandbox = WeberSandbox()
        return _shared_sandbox


def activate_sandbox() -> WeberSandbox:
    """Activate and return the shared WeberSandbox singleton."""
    sandbox = get_sandbox()
    return sandbox.activate()
