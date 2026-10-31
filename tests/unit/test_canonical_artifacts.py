"""Verify that the cross-platform artifact handoff fails closed."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

from repolens import __version__

_CHECKER = Path(__file__).resolve().parents[2] / "tests/installation/check_artifacts.py"


def _verify(
    directory: Path, wheel_digest: str, sdist_digest: str
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["REPOLENS_WHEEL_SHA256"] = wheel_digest
    env["REPOLENS_SDIST_SHA256"] = sdist_digest
    return subprocess.run(
        [sys.executable, str(_CHECKER), "verify-canonical", str(directory)],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def test_canonical_handoff_rejects_tampering_and_unexpected_files(tmp_path: Path) -> None:
    wheel_bytes = b"test wheel"
    sdist_bytes = b"test sdist"
    wheel = tmp_path / f"repolens-{__version__}-py3-none-any.whl"
    sdist = tmp_path / f"repolens-{__version__}.tar.gz"
    wheel.write_bytes(wheel_bytes)
    sdist.write_bytes(sdist_bytes)
    wheel_digest = hashlib.sha256(wheel_bytes).hexdigest()
    sdist_digest = hashlib.sha256(sdist_bytes).hexdigest()

    assert _verify(tmp_path, wheel_digest, sdist_digest).returncode == 0
    assert _verify(tmp_path, "", sdist_digest).returncode != 0
    wheel.write_bytes(b"tampered wheel")
    assert _verify(tmp_path, wheel_digest, sdist_digest).returncode != 0
    wheel.write_bytes(wheel_bytes)
    unexpected = tmp_path / "unexpected.txt"
    unexpected.write_text("unexpected", encoding="utf-8")
    assert _verify(tmp_path, wheel_digest, sdist_digest).returncode != 0
    unexpected.unlink()
    sdist.unlink()
    assert _verify(tmp_path, wheel_digest, sdist_digest).returncode != 0
