"""Inspect release artifacts; the installation workflow runs this outside pytest.

The optional ``seed`` command creates obviously fake local files in a disposable CI
checkout to verify the build allowlist. ``check`` inspects two independent builds and
a direct wheel; ``check-release`` inspects one release-candidate build without rebuilding it.
``verify-canonical`` checks the installation workflow artifact against the build job's hashes.
These commands do not publish anything.
"""

from __future__ import annotations

import base64
import configparser
import contextlib
import csv
import hashlib
import io
import os
import re
import runpy
import sys
import tarfile
import tomllib
import traceback
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import cast

from packaging.requirements import Requirement

_ROOT = Path(__file__).resolve().parents[2]
_SENTINELS = (
    ".env",
    ".repolens-local.toml",
    "src/repolens/.env",
    "src/repolens/private-key.pem",
    "src/repolens/local_credentials.py",
    "src/repolens/settings_local.py",
    "src/repolens/credentials.py",
    "src/repolens/secrets.py",
    "src/repolens/.private.py",
    "src/repolens/.config/settings.py",
    "src/repolens/test_should_not_ship.py",
    "src/repolens/conftest.py",
    "src/repolens/tests/test_should_not_ship.py",
    "src/repolens/__pycache__/should_not_ship.pyc",
)


def seed() -> None:
    """Create harmless sentinel files in a disposable checkout, never overwrite user data."""
    for relative in _SENTINELS:
        file = _ROOT / relative
        if file.exists():
            raise FileExistsError(f"Refusing to overwrite {file}")
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("FAKE_LOCAL_SECRET_MUST_NOT_SHIP\n", encoding="utf-8")
    print("Seeded fake local, secret, cache, and nested test files.")


def clean() -> None:
    """Remove only our exact sentinels; never overwrite or delete unrelated data."""
    parents: set[Path] = set()
    for relative in _SENTINELS:
        file = _ROOT / relative
        if file.read_text(encoding="utf-8") != "FAKE_LOCAL_SECRET_MUST_NOT_SHIP\n":
            raise ValueError(f"Refusing to remove changed file: {file}")
        file.unlink()
        if file.parent != _ROOT:
            parents.add(file.parent)
    for directory in sorted(parents, key=lambda path: len(path.parts), reverse=True):
        with contextlib.suppress(OSError):
            directory.rmdir()  # only if empty
    print("Removed the fake sentinel files from the disposable checkout.")


def _is_runtime_source(path: Path) -> bool:
    name = path.name
    return (
        path.suffix == ".py"
        and "tests" not in path.parts
        and not any(part.startswith(".") for part in path.parts)
        and not name.startswith(("test_", "local_", "credentials_"))
        and not name.endswith(("_local.py", "_credentials.py"))
        and name not in {"conftest.py", "secrets.py", "credentials.py"}
    )


def _digest(path: Path) -> str:
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def _metadata_assertions(raw: bytes, version: str) -> None:
    metadata = BytesParser().parsebytes(raw)
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert metadata["Name"] == project["name"] == "repolens"
    assert metadata["Version"] == version
    assert metadata["Summary"] == project["description"]
    assert metadata["Author"] == ", ".join(author["name"] for author in project["authors"])
    assert metadata["Requires-Python"] == project["requires-python"]
    assert set(metadata.get_all("Classifier", [])) == set(project["classifiers"])
    assert metadata["Description-Content-Type"] == "text/markdown"
    assert "MIT License" in metadata["License"]
    assert "LICENSE" in metadata.get_all("License-File", [])
    description = metadata.get_payload(decode=True)
    assert isinstance(description, bytes)
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert description.decode("utf-8").replace("\r\n", "\n").rstrip() == readme.rstrip()
    assert set(metadata.get_all("Provides-Extra", [])) == set(project["optional-dependencies"])
    assert set(metadata.get_all("Project-URL", [])) == {
        f"{name}, {url}" for name, url in project["urls"].items()
    }
    expected = {Requirement(item) for item in project["dependencies"]}
    for extra, dependencies in project["optional-dependencies"].items():
        expected.update(Requirement(f'{item}; extra == "{extra}"') for item in dependencies)
    assert {Requirement(item) for item in metadata.get_all("Requires-Dist", [])} == expected


def _check_wheel_record(archive: zipfile.ZipFile, names: list[str], record: str) -> None:
    """Check each wheel member against its RECORD digest and size."""
    rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
    assert all(len(row) == 3 for row in rows), "malformed wheel RECORD"
    assert len(rows) == len(names), "wrong number of RECORD entries"
    assert {row[0] for row in rows} == set(names), "duplicate or missing RECORD entries"
    for name, digest, size in rows:
        if name == record:
            assert not digest, "RECORD must not hash itself"
            assert not size, "RECORD must not record its own size"
            continue
        content = archive.read(name)
        expected = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
        assert digest == f"sha256={expected.decode('ascii')}", name
        assert size == str(len(content)), name


def check(first: Path, second: Path | None = None, direct: Path | None = None) -> None:
    """Inspect one candidate or compare the existing independent CI builds as well."""
    if (second is None) != (direct is None):
        raise ValueError("Reproducibility checks require both a second build and a direct wheel")
    version = cast(str, runpy.run_path(str(_ROOT / "src/repolens/_version.py"))["__version__"])
    expected_files = {
        p.relative_to(_ROOT / "src").as_posix()
        for p in (_ROOT / "src/repolens").rglob("*.py")
        if _is_runtime_source(p.relative_to(_ROOT / "src"))
    }
    expected_files.add("repolens/py.typed")
    assert "repolens/_version.py" in expected_files

    wheel = first / f"repolens-{version}-py3-none-any.whl"
    sdist = first / f"repolens-{version}.tar.gz"
    assert set(first.iterdir()) == {wheel, sdist}, "unexpected or missing distribution files"
    for artifact in (wheel, sdist):
        assert artifact.is_file(), artifact
        assert not artifact.is_symlink(), artifact
        digest = _digest(artifact)
        if second is not None:
            assert digest == _digest(second / artifact.name), artifact.name
        print(f"{'reproducible ' if second is not None else ''}sha256 {artifact.name}: {digest}")
    if direct is not None:
        assert _digest(wheel) == _digest(direct / wheel.name), (
            "direct wheel differs from sdist wheel"
        )

    distinfo = f"repolens-{version}.dist-info"
    expected_wheel = expected_files | {
        f"{distinfo}/METADATA",
        f"{distinfo}/WHEEL",
        f"{distinfo}/entry_points.txt",
        f"{distinfo}/licenses/LICENSE",
        f"{distinfo}/RECORD",
    }
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)), "duplicate wheel members"
        assert set(names) == expected_wheel, set(names) ^ expected_wheel
        _check_wheel_record(archive, names, f"{distinfo}/RECORD")
        for name in expected_files:
            assert archive.read(name) == (_ROOT / "src" / name).read_bytes(), name
        _metadata_assertions(archive.read(f"{distinfo}/METADATA"), version)
        assert archive.read(f"{distinfo}/licenses/LICENSE") == (_ROOT / "LICENSE").read_bytes()
        entry_points = configparser.ConfigParser()
        entry_points.read_string(archive.read(f"{distinfo}/entry_points.txt").decode())
        assert entry_points["console_scripts"]["repolens"] == "repolens.cli:main"

    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        assert all(member.isfile() for member in members), "unexpected directory, link or device"
        prefix = f"repolens-{version}/"
        names = [member.name.removeprefix(prefix) for member in members]
        assert all(member.name.startswith(prefix) for member in members)
        assert all(".." not in PurePosixPath(name).parts for name in names)
        assert len(names) == len(set(names)), "duplicate sdist members"
        expected_sdist = {f"src/{name}" for name in expected_files} | {
            ".gitignore",  # Hatchling includes the tracked VCS exclusion file.
            "LICENSE",
            "README.md",
            "pyproject.toml",
            "PKG-INFO",
        }
        assert set(names) == expected_sdist, set(names) ^ expected_sdist
        for name in expected_files:
            content = archive.extractfile(f"{prefix}src/{name}")
            assert content is not None
            assert content.read() == (_ROOT / "src" / name).read_bytes(), name
        metadata_file = archive.extractfile(f"{prefix}PKG-INFO")
        assert metadata_file is not None
        _metadata_assertions(metadata_file.read(), version)
        for filename in ("README.md", "LICENSE"):
            content = archive.extractfile(f"{prefix}{filename}")
            assert content is not None
            assert content.read() == (_ROOT / filename).read_bytes()

    print(
        f"Metadata, entry point, README, license, dependencies and {len(expected_files)} "
        f"package files verified for {version}; no sentinels shipped."
    )


def verify_canonical(directory: Path) -> None:
    """Fail closed if the cross-platform test handoff changed either distribution."""
    version = cast(str, runpy.run_path(str(_ROOT / "src/repolens/_version.py"))["__version__"])
    expected = {
        directory / f"repolens-{version}-py3-none-any.whl": os.environ.get(
            "REPOLENS_WHEEL_SHA256", ""
        ),
        directory / f"repolens-{version}.tar.gz": os.environ.get("REPOLENS_SDIST_SHA256", ""),
    }
    assert set(directory.iterdir()) == set(expected), "unexpected or missing canonical files"
    for path, digest in expected.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"invalid expected SHA-256: {path.name}"
        assert path.is_file(), f"not a regular file: {path}"
        assert not path.is_symlink(), f"symbolic link in canonical artifacts: {path}"
        assert _digest(path) == digest, f"canonical artifact hash mismatch: {path.name}"
        print(f"canonical sha256 {path.name}: {digest}")


def main() -> None:
    if sys.argv[1:] == ["seed"]:
        seed()
    elif sys.argv[1:] == ["clean"]:
        clean()
    elif len(sys.argv) == 5 and sys.argv[1] == "check":
        check(*(Path(arg) for arg in sys.argv[2:]))
    elif len(sys.argv) == 3 and sys.argv[1] == "check-release":
        check(Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "verify-canonical":
        verify_canonical(Path(sys.argv[2]))
    else:
        raise SystemExit(
            "Usage: check_artifacts.py seed | clean | check FIRST SECOND DIRECT "
            "| check-release DIRECTORY | verify-canonical DIRECTORY"
        )


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
