"""Safe, timeout-bounded, environment-sanitized subprocess execution for external scanners."""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from repolens.exceptions import SubprocessExecutionError
from repolens.redaction import redact_secrets

_ALLOWED_ENV_KEYS: tuple[str, ...] = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "PATHEXT",
)

# Windows has no process sessions: a tool launched through a ``.cmd`` shim runs under
# ``cmd.exe``, so terminating only the direct child would leave the real analyzer alive.
# A dedicated process group plus ``taskkill /T`` lets RepoLens stop the whole tree. The
# flags are spelled out because ``subprocess`` only exposes them on Windows builds, which
# would otherwise break importing and type checking on other platforms.
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW = 0x08000000
_CREATION_FLAGS: int = _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW if os.name == "nt" else 0

_FORCED_SAFE_ENV: dict[str, str] = {
    "CI": "1",
    "NO_COLOR": "1",
    "TERM": "dumb",
    "GIT_TERMINAL_PROMPT": "0",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "NODE_NO_WARNINGS": "1",
}


@dataclass(frozen=True, slots=True)
class SubprocessResult:
    """Outcome of a bounded external command invocation."""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    output_truncated: bool = False

    def redacted_stderr(self, *, max_length: int = 500) -> str:
        """Return ``stderr`` scrubbed of any secrets and length-bounded."""
        return redact_secrets(self.stderr, max_length=max_length)


def build_sanitized_env(extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Construct a minimal allowlist environment excluding host credentials."""
    env: dict[str, str] = {}
    for key in _ALLOWED_ENV_KEYS:
        val = os.environ.get(key)
        if val is not None:
            env[key] = val

    env.update(_FORCED_SAFE_ENV)

    if extra_env:
        for key, value in extra_env.items():
            if not key or "\x00" in key or "\x00" in value or "=" in key:
                raise SubprocessExecutionError(f"Invalid environment variable entry: {key!r}")
            env[key] = value

    return env


def _read_bounded_stream(
    stream: IO[bytes] | None,
    max_bytes: int,
    sink: list[bytes],
    truncated_flag: list[bool],
) -> None:
    if stream is None:
        return
    collected = 0
    chunk_size = 16_384
    try:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            remaining = max_bytes - collected
            if remaining > 0:
                if len(chunk) <= remaining:
                    sink.append(chunk)
                    collected += len(chunk)
                else:
                    sink.append(chunk[:remaining])
                    collected += remaining
                    truncated_flag[0] = True
            else:
                truncated_flag[0] = True
    finally:
        stream.close()


def _terminate_windows_process_tree(proc: subprocess.Popen[bytes]) -> None:
    """Terminate ``proc`` and its descendants with ``taskkill``, falling back to ``kill``."""
    taskkill = shutil.which("taskkill")
    if taskkill is not None:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(
                [taskkill, "/F", "/T", "/PID", str(proc.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5.0,
                check=False,
            )
    with contextlib.suppress(OSError):
        proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=1.0)


def _terminate_process_tree(proc: subprocess.Popen[bytes]) -> None:
    """Terminate a timed-out process and any child processes it started."""
    if proc.poll() is not None:
        return

    if os.name == "nt":  # pragma: no cover - exercised on Windows CI only
        _terminate_windows_process_tree(proc)
        return

    killpg_available = hasattr(os, "killpg")
    if killpg_available:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            proc.terminate()
    else:
        proc.terminate()

    try:
        proc.wait(timeout=0.5)
        return
    except subprocess.TimeoutExpired:
        pass

    if killpg_available:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except OSError:
            proc.kill()
    else:
        proc.kill()

    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=1.0)


def run_safe_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float = 30.0,
    max_output_bytes: int = 5_242_880,
    extra_env: Mapping[str, str] | None = None,
) -> SubprocessResult:
    """Execute ``argv`` without a shell, with sanitized env, output caps, and hard timeout."""
    if isinstance(argv, (str, bytes)):
        raise SubprocessExecutionError("argv must be a sequence of arguments, never a shell string")
    if not argv:
        raise SubprocessExecutionError("argv must contain at least the executable name")

    validated_argv: list[str] = []
    for idx, arg in enumerate(argv):
        if not isinstance(arg, str) or "\x00" in arg:
            raise SubprocessExecutionError(f"Invalid argument at index {idx}")
        if idx == 0 and not arg.strip():
            raise SubprocessExecutionError("Executable name must not be empty")
        validated_argv.append(arg)

    if timeout_seconds <= 0:
        raise SubprocessExecutionError("timeout_seconds must be positive")
    if max_output_bytes < 1024:
        raise SubprocessExecutionError("max_output_bytes must be at least 1024")

    if cwd.is_symlink() or not cwd.exists() or not cwd.is_dir():
        raise SubprocessExecutionError(f"Invalid or unsafe working directory: {cwd}")
    resolved_cwd = cwd.resolve(strict=True)

    sanitized_env = build_sanitized_env(extra_env)
    executable = shutil.which(validated_argv[0], path=sanitized_env.get("PATH"))
    if executable is None:
        raise SubprocessExecutionError(f"Executable not found on PATH: {validated_argv[0]}")
    validated_argv[0] = executable

    start_time = time.perf_counter()
    proc = subprocess.Popen(
        validated_argv,
        cwd=resolved_cwd,
        env=sanitized_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
        creationflags=_CREATION_FLAGS,
    )

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_truncated = [False]
    stderr_truncated = [False]

    stdout_thread = threading.Thread(
        target=_read_bounded_stream,
        args=(proc.stdout, max_output_bytes, stdout_chunks, stdout_truncated),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_read_bounded_stream,
        args=(proc.stderr, max_output_bytes, stderr_chunks, stderr_truncated),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(proc)

    stdout_thread.join(timeout=2.0)
    stderr_thread.join(timeout=2.0)

    duration_ms = (time.perf_counter() - start_time) * 1000.0
    stdout_text = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")

    return SubprocessResult(
        argv=tuple(validated_argv),
        returncode=None if timed_out else proc.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        duration_ms=duration_ms,
        timed_out=timed_out,
        output_truncated=stdout_truncated[0] or stderr_truncated[0],
    )
