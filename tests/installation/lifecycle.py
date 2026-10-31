"""Exercise installed artifacts and source lifecycles in disposable virtual environments.

This is run by the installation workflow, not by the network-free pytest suite. All
commands use the environment's own interpreter and execute outside the checkout.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import cast

from packaging.version import Version

_ROOT = Path(__file__).resolve().parents[2]
_BASE_REPO = "CalebPiusC/RepoLens"
_OLD_COMMIT = "e2d832764eb521c17a8f3ac6ed0906420a114ac3"
_BASE_COMMIT = "f4c0f46c475135f9116afb6469b216cb4ebf02bd"
_DEV0_COMMIT = "2305fd975c9d7567cbab64094b22b648d7f209cb"


def _run(
    args: list[str], *, cwd: Path, env: dict[str, str], expect_success: bool = True
) -> subprocess.CompletedProcess[str]:
    print(f"+ {shlex.join(args)}", flush=True)
    result = subprocess.run(  # fixed executable/arguments; the fixture is test-controlled
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=360,
        check=False,
    )
    if (result.returncode == 0) != expect_success:
        raise RuntimeError(f"Exit {result.returncode}: {shlex.join(args)}\n{result.stdout}")
    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    return result


def fixture(root: Path) -> None:
    """Write a small real project that scans cleanly without optional analyzers."""
    files = {
        "LICENSE": "MIT License\nCopyright (c) 2026 Test\n",
        "README.md": "# Sample Python Repo\n\nA healthy test repository.\n",
        ".gitignore": "__pycache__/\n*.py[codz]\n.venv/\n.env\ndist/\n",
        "pyproject.toml": (
            '[project]\nname = "sample"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
            '\n[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
        ),
        "src/sample/__init__.py": '"""Sample package."""\n',
        "src/sample/core.py": "def add(a: int, b: int) -> int:\n    return a + b\n",
        "tests/test_core.py": (
            "from sample.core import add\n\n\ndef test_add() -> None:\n    assert add(1, 2) == 3\n"
        ),
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(f"Created clean scan fixture: {root}")


def _base_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(key, None)
    env.update({"PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1", "PYTHONUTF8": "1"})
    return env


class Env:
    """A fresh venv with a clean working directory and explicit executable paths."""

    def __init__(self, root: Path, project: Path) -> None:
        self.root = root
        self.project = project
        self.env = _base_env()
        _run([sys.executable, "-m", "venv", str(root)], cwd=project, env=self.env)
        self.scripts = root / ("Scripts" if os.name == "nt" else "bin")
        self.python = self.scripts / ("python.exe" if os.name == "nt" else "python")
        self.launcher = self.scripts / ("repolens.exe" if os.name == "nt" else "repolens")
        self.env["PATH"] = f"{self.scripts}{os.pathsep}{self.env.get('PATH', '')}"

    def run(
        self, *args: str, no_git: bool = False, expect_success: bool = True
    ) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        if no_git:
            # Keep Windows environment variables such as SYSTEMROOT, but remove all PATH entries
            # except the venv. This also keeps the scan independent of external tool installs.
            env["PATH"] = str(self.scripts)
        return _run(list(args), cwd=self.project, env=env, expect_success=expect_success)

    def pip(
        self, *args: str, no_git: bool = False, expect_success: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            str(self.python), "-m", "pip", *args, no_git=no_git, expect_success=expect_success
        )

    def python_code(self, code: str) -> str:
        return self.run(str(self.python), "-c", code).stdout.strip()

    def version(self) -> str:
        return self.python_code("import importlib.metadata as m; print(m.version('repolens'))")

    def direct_url(self) -> dict[str, object]:
        raw = self.python_code(
            "import importlib.metadata as m; "
            "print(m.distribution('repolens').read_text('direct_url.json'))"
        )
        return cast(dict[str, object], json.loads(raw))

    def smoke(self, expected_version: str) -> None:
        assert self.version() == expected_version
        assert self.launcher.is_file(), self.launcher
        resolved = shutil.which("repolens", path=self.env["PATH"])
        assert resolved is not None
        assert Path(resolved).resolve() == self.launcher.resolve()
        assert (
            self.run(str(self.launcher), "--version").stdout.strip()
            == f"repolens {expected_version}"
        )
        assert self.run(str(self.python), "-m", "repolens", "--version").stdout.strip() == (
            f"repolens {expected_version}"
        )
        help_text = self.run(str(self.launcher), "--help").stdout
        assert "usage: repolens" in help_text
        assert "scan" in help_text
        self.python_code(
            "from pathlib import Path; import importlib.metadata as m, repolens, sys; "
            "assert repolens.__version__ == m.version('repolens'); "
            "assert sys.prefix != sys.base_prefix; "
            "assert Path(repolens.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())"
        )
        self.pip("check")
        terminal = self.run(str(self.launcher), "scan", ".", "--color", "never", no_git=True)
        assert "No findings detected." in terminal.stdout
        machine = self.run(
            str(self.python), "-m", "repolens", "scan", ".", "--format", "json", no_git=True
        )
        report = json.loads(machine.stdout)
        assert report["schema_version"] == "1.1.0"
        assert report["repolens_version"] == expected_version
        assert report["result"]["exit_code"] == 0

    def uninstall(self) -> None:
        self.pip("uninstall", "--yes", "repolens")
        assert not self.launcher.exists(), f"launcher remained after uninstall: {self.launcher}"
        self.python_code(
            "import importlib.util; assert importlib.util.find_spec('repolens') is None"
        )
        self.pip("show", "repolens", expect_success=False)
        self.pip("check")


def _archive(repository: str, commit: str) -> str:
    return f"https://github.com/{repository}/archive/{commit}.zip"


def wheel_lifecycle(dist: Path, version: str) -> None:
    wheel = dist / f"repolens-{version}-py3-none-any.whl"
    sdist = dist / f"repolens-{version}.tar.gz"
    assert wheel.is_file()
    assert sdist.is_file()
    assert Version(version) > Version("0.1.1.dev0")
    with tempfile.TemporaryDirectory(prefix="rl-wheel-") as directory:
        root = Path(directory)
        project = root / "sample"
        fixture(project)

        wheel_env = Env(root / "wheel-venv", project)
        wheel_env.pip("install", str(wheel.resolve()))
        wheel_env.python_code(
            "import importlib.metadata as m; "
            "installed = {d.metadata['Name'].lower() for d in m.distributions()}; "
            "assert 'ruff' not in installed and 'bandit' not in installed"
        )
        wheel_env.smoke(version)
        wheel_env.pip("install", f"repolens[tools] @ {wheel.resolve().as_uri()}")
        wheel_env.python_code(
            "import importlib.metadata as m; m.version('ruff'); m.version('bandit')"
        )
        wheel_env.pip("check")
        wheel_env.uninstall()

        source_env = Env(root / "sdist-venv", project)
        source_env.pip("install", str(sdist.resolve()))
        source_env.smoke(version)
        source_env.uninstall()

        # A local wheelhouse simulates an index: pip chooses a newer, distinct version.
        # --pre is necessary because the current build is a development pre-release.
        wheelhouse = root / "wheelhouse"
        wheelhouse.mkdir()
        shutil.copy2(wheel, wheelhouse / wheel.name)
        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(wheelhouse),
                _archive(_BASE_REPO, _BASE_COMMIT),
            ],
            cwd=project,
            env=_base_env(),
        )
        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(wheelhouse),
                _archive(_BASE_REPO, _DEV0_COMMIT),
            ],
            cwd=project,
            env=_base_env(),
        )
        old_wheels = list(wheelhouse.glob("repolens-0.1.0-*.whl"))
        dev0_wheels = list(wheelhouse.glob("repolens-0.1.1.dev0-*.whl"))
        assert len(old_wheels) == 1, old_wheels
        assert len(dev0_wheels) == 1, dev0_wheels
        upgrade_env = Env(root / "upgrade-venv", project)
        upgrade_env.pip("install", str(old_wheels[0]))
        assert upgrade_env.version() == "0.1.0"
        upgrade_env.pip(
            "install",
            "--upgrade",
            "--pre",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "repolens",
        )
        assert upgrade_env.version() == version
        # The old dev0 was also downloadable from source. Verify it upgrades without a
        # forced reinstall now that the preparation revision has a distinct version.
        upgrade_env.pip("install", str(dev0_wheels[0]))
        assert upgrade_env.version() == "0.1.1.dev0"
        upgrade_env.pip(
            "install",
            "--upgrade",
            "--pre",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "repolens",
        )
        upgrade_env.smoke(version)
        upgrade_env.uninstall()
    print("Wheel, sdist, tools extra, 0.1.0/dev0 upgrades and uninstall passed.")


def source_lifecycle(repository: str, head: str, version: str) -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", head), head
    assert re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), repository
    with tempfile.TemporaryDirectory(prefix="rl-source-") as directory:
        root = Path(directory)
        project = root / "sample"
        fixture(project)
        git_url = f"git+https://github.com/{_BASE_REPO}.git"
        new_git_url = f"git+https://github.com/{repository}.git@{head}"

        git_env = Env(root / "git-venv", project)
        git_env.pip("install", f"{git_url}@{_OLD_COMMIT}")
        assert cast(dict[str, str], git_env.direct_url()["vcs_info"])["commit_id"] == _OLD_COMMIT
        git_env.pip("install", "--upgrade", f"{git_url}@{_BASE_COMMIT}")
        assert cast(dict[str, str], git_env.direct_url()["vcs_info"])["commit_id"] == _OLD_COMMIT
        git_env.pip("install", "--force-reinstall", "--no-deps", f"{git_url}@{_BASE_COMMIT}")
        assert cast(dict[str, str], git_env.direct_url()["vcs_info"])["commit_id"] == _BASE_COMMIT
        git_env.pip("install", "--upgrade", f"{git_url}@{_DEV0_COMMIT}")
        assert cast(dict[str, str], git_env.direct_url()["vcs_info"])["commit_id"] == _DEV0_COMMIT
        assert git_env.version() == "0.1.1.dev0"
        git_env.pip("install", "--upgrade", new_git_url)
        assert cast(dict[str, str], git_env.direct_url()["vcs_info"])["commit_id"] == head
        git_env.smoke(version)
        git_env.uninstall()

        archive_env = Env(root / "archive-venv", project)
        missing_git = archive_env.pip(
            "install", f"{git_url}@{_BASE_COMMIT}", no_git=True, expect_success=False
        )
        assert "Cannot find command 'git'" in missing_git.stdout, missing_git.stdout
        old_archive = _archive(_BASE_REPO, _OLD_COMMIT)
        base_archive = _archive(_BASE_REPO, _BASE_COMMIT)
        dev0_archive = _archive(_BASE_REPO, _DEV0_COMMIT)
        new_archive = _archive(repository, head)
        archive_env.pip("install", old_archive, no_git=True)
        assert archive_env.direct_url()["url"] == old_archive
        archive_env.pip("install", "--upgrade", base_archive, no_git=True)
        assert archive_env.direct_url()["url"] == old_archive
        archive_env.pip("install", "--force-reinstall", "--no-deps", base_archive, no_git=True)
        assert archive_env.direct_url()["url"] == base_archive
        archive_env.pip("install", "--upgrade", dev0_archive, no_git=True)
        assert archive_env.direct_url()["url"] == dev0_archive
        assert archive_env.version() == "0.1.1.dev0"
        archive_env.pip("install", "--upgrade", new_archive, no_git=True)
        assert archive_env.direct_url()["url"] == new_archive
        archive_env.smoke(version)
        # The documented PEP 508 extra works for a Git-free source archive too.
        archive_env.pip("install", f"repolens[tools] @ {new_archive}", no_git=True)
        archive_env.python_code(
            "import importlib.metadata as m; m.version('ruff'); m.version('bandit')"
        )
        archive_env.pip("check", no_git=True)
        archive_env.uninstall()
    print(
        "Git and Git-free pinned archives: same-version retention, forced reinstall, "
        "distinct-version upgrade, missing Git and uninstall passed."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("fixture", "wheel", "source"))
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--head")
    args = parser.parse_args()
    version = cast(str, runpy.run_path(str(_ROOT / "src/repolens/_version.py"))["__version__"])
    if args.mode == "fixture":
        assert args.directory is not None
        fixture(args.directory)
    elif args.mode == "wheel":
        assert args.directory is not None
        wheel_lifecycle(args.directory, version)
    else:
        assert args.repository is not None
        assert args.head is not None
        source_lifecycle(args.repository, args.head, version)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            detail = (
                traceback.format_exc()[-8000:]
                .replace("%", "%25")
                .replace("\r", "%0D")
                .replace("\n", "%0A")
            )
            print(f"::error::{detail}", flush=True)
        raise
