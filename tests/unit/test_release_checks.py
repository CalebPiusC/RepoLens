"""Exercise release guards without creating tags or publishing packages."""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "installation/release_checks.py"
_SPEC = importlib.util.spec_from_file_location("repolens_release_checks", _SCRIPT)
assert _SPEC is not None
assert _SPEC.loader is not None
release = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(release)


@pytest.mark.parametrize(
    ("tag", "version"),
    [
        ("v0.1.1.dev1", "0.1.1.dev1"),
        ("v0.1.1", "0.1.1.dev1"),
        ("v0.1.1rc1", "0.1.1rc1"),
        ("v0.1.1.post1", "0.1.1.post1"),
        ("v0.1.1+local", "0.1.1+local"),
        ("v0.01.1", "0.01.1"),
        ("v0.1.2", "0.1.1"),
        ("0.1.1", "0.1.1"),
        ("v0.1.1/extra", "0.1.1"),
    ],
)
def test_tag_guard_rejects_nonfinal_or_mismatched_versions(tag: str, version: str) -> None:
    with pytest.raises(ValueError, match=r"Production requires|does not match"):
        release.validate_tag(tag, version)


def test_tag_guard_accepts_only_matching_final_version() -> None:
    assert release.validate_tag("v0.1.1", "0.1.1") == "0.1.1"
    assert release.validate_tag("v1.2.3", "1.2.3") == "1.2.3"


def test_static_version_is_read_without_executing_source(tmp_path: Path) -> None:
    version_file = tmp_path / "version.py"
    version_file.write_text('__version__ = "0.1.1"\nraise RuntimeError("do not run")\n')
    assert release.read_static_version(version_file) == "0.1.1"
    version_file.write_text('__version__ = "0.1.1"\n__version__ = "0.1.2"\n')
    with pytest.raises(ValueError, match="exactly one"):
        release.read_static_version(version_file)
    version_file.write_text('__version__ = "0.1." + "1"\n')
    with pytest.raises(ValueError, match="malformed node"):
        release.read_static_version(version_file)


def _event() -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": "CalebPiusC/RepoLens",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF_TYPE": "tag",
        "GITHUB_REF_NAME": "v0.1.1",
        "GITHUB_REF": "refs/tags/v0.1.1",
        "GITHUB_SHA": "a" * 40,
    }


def test_ref_guard_checks_tag_and_main_ancestry() -> None:
    calls: list[tuple[str, ...]] = []

    def git(*args: str) -> str:
        calls.append(args)
        return "" if args[0] == "merge-base" else "b" * 40

    release.verify_ref(_event(), git)
    assert len(calls) == 4
    assert calls[-1] == ("merge-base", "--is-ancestor", "b" * 40, "refs/remotes/origin/main")


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_REPOSITORY", "another/repository"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REF_TYPE", "branch"),
        ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_REF_NAME", "main"),
        ("GITHUB_SHA", "not-a-sha"),
    ],
)
def test_ref_guard_rejects_non_tag_events(key: str, value: str) -> None:
    env = _event()
    env[key] = value
    with pytest.raises(ValueError, match=r"restricted|tag-push|expected version tag|Invalid"):
        release.verify_ref(env, lambda *_args: "a" * 40)


def test_ref_guard_rejects_moved_tag_and_unmerged_commit() -> None:
    def moved(*args: str) -> str:
        return "c" * 40 if "refs/tags/v0.1.1^{commit}" in args else "b" * 40

    with pytest.raises(ValueError, match="commits do not match"):
        release.verify_ref(_event(), moved)

    def unmerged(*args: str) -> str:
        if args[0] == "merge-base":
            raise RuntimeError("not on main")
        return "b" * 40

    with pytest.raises(RuntimeError, match="not on main"):
        release.verify_ref(_event(), unmerged)


def test_readme_guard_rejects_stale_status_and_version() -> None:
    readme = "# Example\n$ repolens --version\nrepolens 0.1.1\n"
    release.check_readme(readme, "0.1.1")
    for phrase in ("not published to PyPI", "PyPI (not yet published)", "not available yet"):
        with pytest.raises(ValueError, match="pending-PyPI"):
            release.check_readme(readme + phrase, "0.1.1")
    with pytest.raises(ValueError, match="version example"):
        release.check_readme(readme.replace("repolens 0.1.1", "repolens 0.1.1.dev1"), "0.1.1")


def test_artifact_handoff_rejects_tampering_or_extra_files(tmp_path: Path) -> None:
    wheel = tmp_path / "repolens-0.1.1-py3-none-any.whl"
    sdist = tmp_path / "repolens-0.1.1.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    wheel_hash = hashlib.sha256(b"wheel").hexdigest()
    sdist_hash = hashlib.sha256(b"sdist").hexdigest()
    release.verify_distributions(tmp_path, "0.1.1", wheel_hash, sdist_hash)
    with pytest.raises(ValueError, match="Invalid expected"):
        release.verify_distributions(tmp_path, "0.1.1", "", sdist_hash)
    wheel.write_bytes(b"modified")
    with pytest.raises(ValueError, match="hash mismatch"):
        release.verify_distributions(tmp_path, "0.1.1", wheel_hash, sdist_hash)
    wheel.write_bytes(b"wheel")
    extra = tmp_path / "extra.whl"
    extra.write_bytes(b"extra")
    with pytest.raises(ValueError, match="Unexpected or missing"):
        release.verify_distributions(tmp_path, "0.1.1", wheel_hash, sdist_hash)
    extra.unlink()
    sdist.unlink()
    with pytest.raises(ValueError, match="Unexpected or missing"):
        release.verify_distributions(tmp_path, "0.1.1", wheel_hash, sdist_hash)


def _pypi_connection(monkeypatch: pytest.MonkeyPatch, status: int) -> tuple[Mock, Mock]:
    connection = Mock()
    connection.getresponse.return_value.status = status
    factory = Mock(return_value=connection)
    monkeypatch.setattr(http.client, "HTTPSConnection", factory)
    return factory, connection


def test_pypi_guard_allows_only_direct_404(monkeypatch: pytest.MonkeyPatch) -> None:
    factory, connection = _pypi_connection(monkeypatch, 404)
    release.require_unpublished("0.1.1")
    factory.assert_called_once_with("pypi.org", timeout=15)
    connection.request.assert_called_once_with(
        "GET",
        "/pypi/repolens/0.1.1/json",
        headers={"User-Agent": "RepoLens-release-check/1.0"},
    )
    connection.close.assert_called_once_with()


@pytest.mark.parametrize("status", [300, 301, 302, 307, 308, 401, 403, 429, 500, 503])
def test_pypi_guard_rejects_redirects_and_unexpected_http_responses(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    _, connection = _pypi_connection(monkeypatch, status)
    with pytest.raises(RuntimeError, match="Unexpected PyPI HTTP"):
        release.require_unpublished("0.1.1")
    connection.request.assert_called_once()
    connection.close.assert_called_once_with()


def test_pypi_guard_rejects_existing_version_and_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, connection = _pypi_connection(monkeypatch, 200)
    with pytest.raises(RuntimeError, match="already exists"):
        release.require_unpublished("0.1.1")
    connection.request.side_effect = OSError("offline")
    with pytest.raises(RuntimeError, match="Could not verify"):
        release.require_unpublished("0.1.1")
