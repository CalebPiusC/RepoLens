"""The release archive checker verifies wheel RECORD integrity."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import zipfile
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "installation/check_artifacts.py"
_SPEC = importlib.util.spec_from_file_location("repolens_artifact_checks", _SCRIPT)
assert _SPEC is not None
assert _SPEC.loader is not None
checks = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(checks)


def _wheel(path: Path, *, digest: str, record_size: str = "") -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("repolens/example.py", b"example")
        archive.writestr(
            "repolens-0.1.1.dist-info/RECORD",
            f"repolens/example.py,sha256={digest},7\n"
            f"repolens-0.1.1.dist-info/RECORD,,{record_size}\n",
        )


def test_wheel_record_detects_tampering_and_invalid_self_entry(tmp_path: Path) -> None:
    path = tmp_path / "candidate.whl"
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"example").digest()).rstrip(b"=").decode()
    record = "repolens-0.1.1.dist-info/RECORD"
    _wheel(path, digest=digest)
    with zipfile.ZipFile(path) as archive:
        checks._check_wheel_record(archive, archive.namelist(), record)
    _wheel(path, digest="a" * 43)
    with zipfile.ZipFile(path) as archive, pytest.raises(AssertionError):
        checks._check_wheel_record(archive, archive.namelist(), record)
    _wheel(path, digest=digest, record_size="1")
    with zipfile.ZipFile(path) as archive, pytest.raises(AssertionError):
        checks._check_wheel_record(archive, archive.namelist(), record)
