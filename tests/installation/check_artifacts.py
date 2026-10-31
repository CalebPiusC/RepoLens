"""Inspect release artifacts; the installation workflow runs this outside pytest.

The optional ``seed`` command creates obviously fake local files in a disposable CI
checkout to verify the build allowlist. ``check`` inspects two independent builds and
a direct wheel; no uploaded artifact is involved.
"""

from __future__ import annotations

import configparser
import contextlib
import hashlib
import os
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
    assert metadata["Name"] == "repolens"
    assert metadata["Version"] == version
    assert metadata["Requires-Python"] == project["requires-python"]
    assert metadata["Description-Content-Type"] == "text/markdown"
    assert "MIT License" in metadata["License"]
    assert "LICENSE" in metadata.get_all("License-File", [])
    assert "RepoLens" in metadata.get_payload()
    assert set(metadata.get_all("Provides-Extra", [])) == set(project["optional-dependencies"])
    assert set(metadata.get_all("Project-URL", [])) == {
        f"{name}, {url}" for name, url in project["urls"].items()
    }
    expected = {Requirement(item) for item in project["dependencies"]}
    for extra, dependencies in project["optional-dependencies"].items():
        expected.update(Requirement(f'{item}; extra == "{extra}"') for item in dependencies)
    assert {Requirement(item) for item in metadata.get_all("Requires-Dist", [])} == expected


def check(first: Path, second: Path, direct: Path) -> None:
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
    for artifact in (wheel, sdist):
        assert artifact.is_file(), artifact
        assert _digest(artifact) == _digest(second / artifact.name), artifact.name
        print(f"reproducible sha256 {artifact.name}: {_digest(artifact)}")
    assert _digest(wheel) == _digest(direct / wheel.name), "direct wheel differs from sdist wheel"

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


def main() -> None:
    if sys.argv[1:] == ["seed"]:
        seed()
    elif sys.argv[1:] == ["clean"]:
        clean()
    elif len(sys.argv) == 5 and sys.argv[1] == "check":
        check(*(Path(arg) for arg in sys.argv[2:]))
    else:
        raise SystemExit("Usage: check_artifacts.py seed | clean | check FIRST SECOND DIRECT")


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
