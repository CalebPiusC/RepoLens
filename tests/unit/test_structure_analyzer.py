"""Unit tests for StructureAnalyzer and GitIgnoreMatcher."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from repolens.config import ScanConfig
from repolens.discovery import GitIgnoreMatcher
from repolens.engine import ScanEngine
from repolens.models import Severity


def test_healthy_python_repository_produces_zero_findings(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    # Ignored local dev artifacts and safe .env.example should not trigger false positives.
    (repo / ".venv").mkdir()
    (repo / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (repo / ".env").write_text("SECRET_KEY=local_dev_only\n", encoding="utf-8")
    (repo / ".env.example").write_text("SECRET_KEY=changeme\n", encoding="utf-8")

    report = ScanEngine().scan(repo)
    assert report.findings == []


def test_healthy_typescript_repository_produces_zero_findings(
    make_jsts_repo: Callable[..., Path],
) -> None:
    repo = make_jsts_repo()
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "index.js").write_text(
        "module.exports = {};\n", encoding="utf-8"
    )

    report = ScanEngine().scan(repo)
    assert report.findings == []


def test_missing_license_readme_and_gitignore_detected(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo(
        include_license=False,
        include_readme=False,
        include_gitignore=False,
        include_pyproject=False,
    )
    report = ScanEngine().scan(repo)
    rule_ids = {f.rule_id for f in report.findings}
    assert "RL-STRUCT-001" in rule_ids  # missing LICENSE
    assert "RL-STRUCT-002" in rule_ids  # missing README
    assert "RL-STRUCT-003" in rule_ids  # missing .gitignore
    assert "RL-STRUCT-007" in rule_ids  # Python files without manifest


def test_empty_readme_and_incomplete_python_gitignore(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / "README.md").write_text("   \n\t\n", encoding="utf-8")
    (repo / ".gitignore").write_text("dist/\n", encoding="utf-8")

    report = ScanEngine().scan(repo)
    by_rule = {f.rule_id: f for f in report.findings}
    assert "RL-STRUCT-002" in by_rule
    assert "RL-STRUCT-004" in by_rule
    assert "__pycache__" in (by_rule["RL-STRUCT-004"].evidence or "")


def test_unignored_sensitive_files_and_vendor_dirs(
    make_jsts_repo: Callable[..., Path],
) -> None:
    repo = make_jsts_repo(include_gitignore=False, include_lockfile=False)
    (repo / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (repo / "node_modules").mkdir()
    (repo / ".env.production").write_text(
        "DATABASE_URL=postgres://u:secret@db/app\n", encoding="utf-8"
    )
    (repo / "certs").mkdir()
    (repo / "certs" / "server.key").write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8=\n"
        "-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    report = ScanEngine().scan(repo)
    rule_ids = {f.rule_id for f in report.findings}
    assert "RL-STRUCT-005" in rule_ids  # node_modules not in .gitignore
    assert "RL-STRUCT-006" in rule_ids  # unignored node_modules present
    assert "RL-STRUCT-008" in rule_ids  # missing JS lockfile
    assert "RL-SEC-001" in rule_ids

    sec_findings = [f for f in report.findings if f.rule_id == "RL-SEC-001"]
    severities = {f.location.path: f.severity for f in sec_findings if f.location}
    assert severities[".env.production"] == Severity.HIGH
    assert severities["certs/server.key"] == Severity.CRITICAL
    # Verify actual secret material was never read into evidence
    for finding in sec_findings:
        assert "postgres://" not in (finding.evidence or "")
        assert "MIIBVwIBADAN" not in (finding.evidence or "")


def test_conflicting_js_lockfiles_and_malformed_manifests(
    make_jsts_repo: Callable[..., Path],
) -> None:
    repo = make_jsts_repo(include_lockfile=True)
    (repo / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")

    report = ScanEngine().scan(repo)
    assert any(f.rule_id == "RL-STRUCT-009" for f in report.findings)

    # Introduce invalid JSON in package.json and invalid TOML in pyproject.toml
    (repo / "package.json").write_text('{\n  "name": "broken",\n}\n', encoding="utf-8")
    (repo / "pyproject.toml").write_text('[project\nname = "broken"\n', encoding="utf-8")

    broken_report = ScanEngine().scan(repo)
    malformed = [f for f in broken_report.findings if f.rule_id == "RL-STRUCT-011"]
    assert len(malformed) == 2


def test_committed_archive_and_oversized_file_flagged(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / "backup.zip").write_bytes(b"PK\x03\x04dummy")
    (repo / "large_data.csv").write_bytes(b"x" * 4096)

    config = ScanConfig(max_file_size_bytes=2048)
    report = ScanEngine(config=config).scan(repo)
    flagged_paths = {
        f.location.path for f in report.findings if f.rule_id == "RL-STRUCT-010" and f.location
    }
    assert flagged_paths == {"backup.zip", "large_data.csv"}


def test_gitignore_matcher_handles_negation_anchoring_and_globs() -> None:
    matcher = GitIgnoreMatcher(
        "\n".join(
            [
                "# comment",
                "*.py[codz]",
                "/site",
                "build/",
                "secrets/*",
                "!secrets/.keep",
                "**/generated/*.json",
            ]
        )
    )
    assert matcher.is_ignored("pkg/mod.pyc") is True
    assert matcher.is_ignored("site", is_dir=True) is True
    assert matcher.is_ignored("docs/site", is_dir=True) is False
    assert matcher.is_ignored("build", is_dir=False) is False
    assert matcher.is_ignored("build", is_dir=True) is True
    assert matcher.is_ignored("build/output.js", is_dir=False) is True
    assert matcher.is_ignored("secrets/api.txt", is_dir=False) is True
    assert matcher.is_ignored("secrets/.keep", is_dir=False) is False
    assert matcher.is_ignored("a/b/generated/schema.json", is_dir=False) is True
