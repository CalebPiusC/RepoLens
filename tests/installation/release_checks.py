"""Fail-closed checks used by the tag-only publishing workflow.

This script uses only the standard library, including in the protected publish job.
It never uploads a package or creates a tag.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import hmac
import http.client
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_FINAL_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def read_static_version(path: Path) -> str:
    """Read the single literal version assignment without importing project code."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        )
    ]
    if len(assignments) != 1:
        raise ValueError("Expected exactly one static __version__ assignment")
    value = ast.literal_eval(assignments[0].value)
    if not isinstance(value, str):
        raise ValueError("Package version must be a string literal")
    return value


def require_final_version(version: str) -> str:
    """Only canonical three-component final versions are accepted for PyPI."""
    if not _FINAL_VERSION.fullmatch(version):
        raise ValueError("Production requires a final N.N.N version, not a development/pre-release")
    return version


def validate_tag(tag: str, version: str) -> str:
    version = require_final_version(version)
    if tag != f"v{version}":
        raise ValueError(f"Tag {tag!r} does not match package version {version!r}")
    return version


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=_ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"Git release-ref check failed: {result.stderr.strip()}")
    return result.stdout.strip()


def verify_ref(environ: Mapping[str, str], git: Callable[..., str]) -> None:
    """Require the event tag to still point at a commit reachable from main."""
    tag = environ.get("GITHUB_REF_NAME", "")
    ref = environ.get("GITHUB_REF", "")
    sha = environ.get("GITHUB_SHA", "")
    if environ.get("GITHUB_REPOSITORY") != "CalebPiusC/RepoLens":
        raise ValueError("Publishing is restricted to the upstream repository")
    if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF_TYPE") != "tag":
        raise ValueError("Publishing requires a tag-push event")
    if not tag.startswith("v") or ref != f"refs/tags/{tag}":
        raise ValueError("Event ref is not the expected version tag")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid event commit SHA")
    event_commit = git("rev-parse", "--verify", "--end-of-options", f"{sha}^{{commit}}")
    tag_commit = git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
    head_commit = git("rev-parse", "--verify", "HEAD^{commit}")
    if event_commit != tag_commit or event_commit != head_commit:
        raise ValueError("The tag, event, and checked-out commits do not match")
    git("merge-base", "--is-ancestor", event_commit, "refs/remotes/origin/main")


def check_readme(text: str, version: str) -> None:
    """Do not ship a stable artifact whose description still says PyPI is unavailable."""
    require_final_version(version)
    normalized = " ".join(text.casefold().split())
    pending_phrases = (
        "not published to pypi",
        "pypi (not yet published)",
        "currently fails with",
        "not available yet",
    )
    if any(phrase in normalized for phrase in pending_phrases):
        raise ValueError("Update the pending-PyPI README wording before a stable release")
    example = re.search(r"(?m)^\$ repolens --version\nrepolens (\S+)$", text)
    if example is None or example.group(1) != version:
        raise ValueError("README CLI version example does not match the release version")


def verify_distributions(directory: Path, version: str, wheel_hash: str, sdist_hash: str) -> None:
    """Check the exact candidate filenames, file types and build-job SHA-256 outputs."""
    require_final_version(version)
    expected = {
        directory / f"repolens-{version}-py3-none-any.whl": wheel_hash,
        directory / f"repolens-{version}.tar.gz": sdist_hash,
    }
    if set(directory.iterdir()) != set(expected):
        raise ValueError("Unexpected or missing release distributions")
    for path, digest in expected.items():
        if not _SHA256.fullmatch(digest):
            raise ValueError(f"Invalid expected SHA-256 for {path.name}")
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Release distribution is not a regular file: {path.name}")
        with path.open("rb") as artifact:
            actual = hashlib.file_digest(artifact, "sha256").hexdigest()
        if not hmac.compare_digest(actual, digest):
            raise ValueError(f"Release distribution hash mismatch: {path.name}")
        print(f"Verified SHA-256 {path.name}: {actual}")


def require_unpublished(version: str) -> None:
    """Abort on an existing version or any uncertain PyPI response; never follow redirects."""
    require_final_version(version)
    connection = http.client.HTTPSConnection("pypi.org", timeout=15)
    try:
        connection.request(
            "GET",
            f"/pypi/repolens/{version}/json",
            headers={"User-Agent": "RepoLens-release-check/1.0"},
        )
        status = connection.getresponse().status
    except (http.client.HTTPException, OSError) as exc:
        raise RuntimeError(
            "Could not verify PyPI version availability; refusing publication"
        ) from exc
    finally:
        connection.close()
    if status == 404:
        print(f"PyPI version {version} is not currently visible (HTTP 404).")
    elif status == 200:
        raise RuntimeError("PyPI version already exists; refusing publication")
    else:
        raise RuntimeError(f"Unexpected PyPI HTTP {status}; refusing publication")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ref")
    version_parser = commands.add_parser("version")
    version_parser.add_argument("tag")
    readme_parser = commands.add_parser("readme")
    readme_parser.add_argument("version")
    pypi_parser = commands.add_parser("pypi")
    pypi_parser.add_argument("version")
    artifacts_parser = commands.add_parser("artifacts")
    artifacts_parser.add_argument("directory", type=Path)
    artifacts_parser.add_argument("version")
    args = parser.parse_args()
    try:
        if args.command == "ref":
            verify_ref(os.environ, _git)
        elif args.command == "version":
            version = read_static_version(_ROOT / "src/repolens/_version.py")
            print(validate_tag(args.tag, version))
        elif args.command == "readme":
            check_readme((_ROOT / "README.md").read_text(encoding="utf-8"), args.version)
        elif args.command == "pypi":
            require_unpublished(args.version)
        elif args.command == "artifacts":
            verify_distributions(
                args.directory,
                args.version,
                os.environ.get("REPOLENS_WHEEL_SHA256", ""),
                os.environ.get("REPOLENS_SDIST_SHA256", ""),
            )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Release validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
