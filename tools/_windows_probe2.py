"""Temporary Windows probe #2: validate the portable fake-tool design."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

from repolens.analyzers.tooling import clear_tool_cache, probe_tool, run_tool, tool_workspace
from repolens.subprocess_runner import build_sanitized_env, run_safe_command

PREAMBLE = '''\
import json
import os
import sys
import time
from pathlib import Path

_args = sys.argv[1:]
'''


def show(label: str, value: object) -> None:
    print(f"PROBE {label}: {value!r}")


tmp = Path(tempfile.mkdtemp())
bin_dir = tmp / "bin"
bin_dir.mkdir()

impl = bin_dir / "ruff-stub.py"
impl.write_text(
    PREAMBLE
    + 'Path(r"' + str(tmp / "args.json") + '").write_text(json.dumps(_args), encoding="utf-8")\n'
    + "print(json.dumps([]))\n",
    encoding="utf-8",
)
launcher = bin_dir / "ruff.cmd"
launcher.write_text(f'@echo off\r\n"{sys.executable}" "{impl}" %*\r\n', encoding="utf-8")

sleep_impl = bin_dir / "sleepy.py"
sleep_impl.write_text(PREAMBLE + "time.sleep(30)\n", encoding="utf-8")
sleep_launcher = bin_dir / "sleepy.cmd"
sleep_launcher.write_text(f'@echo off\r\n"{sys.executable}" "{sleep_impl}" %*\r\n', encoding="utf-8")

version_impl = bin_dir / "sleeper.py"
version_impl.write_text(
    PREAMBLE + 'if _args[:1] == ["--version"]:\n    print("ruff 0.9.7")\nraise SystemExit(0)\n',
    encoding="utf-8",
)
version_launcher = bin_dir / "probetool.cmd"
version_launcher.write_text(f'@echo off\r\n"{sys.executable}" "{version_impl}" %*\r\n', encoding="utf-8")

os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
clear_tool_cache()

show("which_ruff", shutil.which("ruff"))
show("sanitized_has_comspec", "COMSPEC" in build_sanitized_env())
show("comspec_present_in_os", "COMSPEC" in os.environ)

tricky = ["--flag", "value with spaces", "a;b", "--config-path=C:\\x\\y", "src/demo/core.py"]
with tool_workspace() as workspace:
    try:
        result = run_safe_command(["ruff", *tricky], cwd=workspace, timeout_seconds=20.0)
        show("run_rc", result.returncode)
        show("run_stderr", result.stderr[:300])
    except Exception as exc:  # noqa: BLE001
        show("run_exc", f"{type(exc).__name__}: {exc}")
    show("received_args", (tmp / "args.json").read_text(encoding="utf-8") if (tmp / "args.json").exists() else "MISSING")

show("probe_probetool", probe_tool("probetool"))

start = time.perf_counter()
with tool_workspace() as workspace:
    try:
        timed = run_tool("sleepy", [], cwd=workspace, timeout_seconds=0.5, max_output_bytes=4096)
        show("timeout_result", (timed.timed_out, timed.returncode))
    except Exception as exc:  # noqa: BLE001
        show("timeout_exc", f"{type(exc).__name__}: {exc}")
show("timeout_elapsed", round(time.perf_counter() - start, 2))
