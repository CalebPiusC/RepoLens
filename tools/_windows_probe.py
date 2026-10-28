"""Temporary Windows capability probe (deleted once the suite is green)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def show(label: str, value: object) -> None:
    print(f"PROBE {label}: {value!r}")


print(f"PROBE platform: {sys.platform}")
print(f"PROBE python: {sys.version.split()[0]}")

tmp = Path(tempfile.mkdtemp())

# --- symlinks ---------------------------------------------------------------
target = tmp / "target.txt"
target.write_text("x")
try:
    link = tmp / "link.txt"
    link.symlink_to(target)
    show("symlink_file", "ok")
except OSError as exc:
    show("symlink_file", f"{type(exc).__name__}: {exc}")

try:
    d = tmp / "realdir"
    d.mkdir()
    dl = tmp / "dirlink"
    dl.symlink_to(d, target_is_directory=True)
    show("symlink_dir", "ok")
except OSError as exc:
    show("symlink_dir", f"{type(exc).__name__}: {exc}")

# junction (no privilege needed) as an alternative
try:
    j = tmp / "junction"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(j), str(d)], check=True, capture_output=True)
    show("junction", f"ok islink={j.is_symlink()}")
except Exception as exc:  # noqa: BLE001
    show("junction", f"{type(exc).__name__}: {exc}")

# --- chmod ------------------------------------------------------------------
locked = tmp / "locked"
locked.mkdir()
(locked / "secret.py").write_text("secret = 1\n")
try:
    locked.chmod(0o000)
    try:
        entries = list(os.scandir(locked))
        show("chmod000_scandir", f"still readable ({len(entries)} entries)")
    except OSError as exc:
        show("chmod000_scandir", f"blocked: {type(exc).__name__}")
finally:
    try:
        locked.chmod(0o755)
    except OSError:
        pass

# --- long paths -------------------------------------------------------------
deep = tmp / "deep"
cur = deep
for i in range(64):
    cur = cur / f"n{i}"
try:
    cur.mkdir(parents=True)
    (cur / "unreachable").mkdir()
    (cur / "unreachable" / "broken.py").write_text("def broken(:\n")
    show("depth64_len", len(str(cur)))
    show("depth64", "ok")
except OSError as exc:
    show("depth64", f"{type(exc).__name__}: errno={getattr(exc, 'errno', None)} {exc}")

# max single path length test
for n in (120, 200, 250, 300):
    p = tmp / ("p" * 1) / ("a" * n)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
        show(f"pathlen_{n}", "ok")
    except OSError as exc:
        show(f"pathlen_{n}", f"{type(exc).__name__}: errno={getattr(exc, 'errno', None)}")

# --- expanduser -------------------------------------------------------------
os.environ["HOME"] = str(tmp / "fakehome")
show("expanduser_with_HOME", str(Path("~/x").expanduser()))
show("USERPROFILE", os.environ.get("USERPROFILE"))

# --- fake tool execution ----------------------------------------------------
bindir = tmp / "bin"
bindir.mkdir()

shell_stub = bindir / "shelltool"
shell_stub.write_text('#!/bin/sh\necho "shelltool 1.2.3"\n')
try:
    shell_stub.chmod(0o755)
except OSError:
    pass

cmd_stub = bindir / "cmdtool.cmd"
cmd_stub.write_text("@echo off\r\necho cmdtool 1.2.3\r\n")
py_stub = bindir / "pytool.py"
py_stub.write_text('import sys\nprint("pytool 1.2.3", sys.argv[1:])\n')

os.environ["PATH"] = f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
for name in ("shelltool", "cmdtool", "pytool"):
    show(f"which_{name}", shutil.which(name))
show("PATHEXT", os.environ.get("PATHEXT"))
show("which_sh", shutil.which("sh"))

def try_run(label: str, argv: list[str]) -> None:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
        show(label, (proc.returncode, proc.stdout.strip()[:120], proc.stderr.strip()[:200]))
    except Exception as exc:  # noqa: BLE001
        show(label, f"{type(exc).__name__}: {exc}")

try_run("run_cmd_stub", [str(cmd_stub), "--version"])
try_run("run_cmd_stub_args", [str(cmd_stub), "--flag", "value with spaces", "a;b"])
try_run("run_py_stub", [str(py_stub), "--version"])
try_run("run_shell_stub", [str(shell_stub), "--version"])
try_run("run_via_which_cmd", [shutil.which("cmdtool"), "--version"])

py_in_bindir = bindir / "pytool2.py"
py_in_bindir.write_text('import sys\nprint("pytool2 2.0.0", sys.argv[1:])\n')
os.environ["PATHEXT"] = os.environ.get("PATHEXT", "") + ";.PY"
show("which_pytool2_with_PY", shutil.which("pytool2"))

# --- subprocess kwargs on windows ------------------------------------------
try:
    proc = subprocess.run(
        [sys.executable, "-c", "import sys; print(sys.argv[1:])", "--flag", "value with spaces"],
        capture_output=True,
        text=True,
        start_new_session=True,
        check=False,
    )
    show("start_new_session", (proc.returncode, proc.stdout.strip(), proc.stderr.strip()[:200]))
except Exception as exc:  # noqa: BLE001
    show("start_new_session", f"{type(exc).__name__}: {exc}")

# --- process group kill -----------------------------------------------------
try:
    p = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
        shell=False,
    )
    p.terminate()
    show("proc_terminate", f"rc={p.wait(timeout=10)}")
except Exception as exc:  # noqa: BLE001
    show("proc_terminate", f"{type(exc).__name__}: {exc}")

show("has_killpg", hasattr(os, "killpg"))
