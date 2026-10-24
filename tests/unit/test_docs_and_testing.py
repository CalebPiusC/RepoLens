"""Unit tests for documentation consistency and testing hygiene analyzers."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from repolens.analyzers.documentation import DocumentationAnalyzer
from repolens.analyzers.testing import TestingAnalyzer as HygieneAnalyzer
from repolens.config import ScanConfig
from repolens.discovery import RepositoryContext, discover_repository


def _context(root: Path) -> RepositoryContext:
    return discover_repository(root, ScanConfig())


def _rules(context: RepositoryContext, analyzer: object) -> dict[str, object]:
    findings = analyzer.analyze(context, ScanConfig())  # type: ignore[attr-defined]
    return {finding.rule_id: finding for finding in findings}


# --------------------------------------------------------------------------------------
# Documentation
# --------------------------------------------------------------------------------------


def test_missing_manifest_readme_reference_is_reported(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nreadme = "docs/README.md"\n', encoding="utf-8"
    )
    findings = _rules(_context(root), DocumentationAnalyzer())
    assert "RL-DOC-001" in findings


def test_existing_manifest_readme_reference_is_clean(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nreadme = "README.md"\n', encoding="utf-8"
    )
    (root / "README.md").write_text("# Demo\n", encoding="utf-8")
    assert _rules(_context(root), DocumentationAnalyzer()) == {}


def test_missing_manifest_license_file_is_reported(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nlicense = { file = "LICENSE" }\n', encoding="utf-8"
    )
    findings = _rules(_context(root), DocumentationAnalyzer())
    assert "RL-DOC-002" in findings


def test_broken_readme_links_are_reported_but_external_links_are_not(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text(
        "# Demo\n\n"
        "[Guide](docs/guide.md)\n"
        "[Site](https://example.com)\n"
        "[Anchor](#usage)\n"
        "[Present](LICENSE)\n"
        "[Template]({{ cookiecutter.repo }})\n",
        encoding="utf-8",
    )
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    findings = _rules(_context(root), DocumentationAnalyzer())
    assert "RL-DOC-003" in findings
    finding = findings["RL-DOC-003"]
    assert "docs/guide.md" in finding.title  # type: ignore[attr-defined]
    assert finding.location is not None  # type: ignore[attr-defined]
    assert finding.location.start_line == 3  # type: ignore[attr-defined]


def test_documentation_directory_links_are_accepted(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "docs").mkdir()
    (root / "docs" / "index.md").write_text("# Docs\n", encoding="utf-8")
    (root / "README.md").write_text("[Docs](docs)\n", encoding="utf-8")
    assert _rules(_context(root), DocumentationAnalyzer()) == {}


def test_license_declaration_mismatch_is_reported(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nlicense = "Apache-2.0"\n', encoding="utf-8"
    )
    (root / "LICENSE").write_text(
        "MIT License\n\nPermission is hereby granted, free of charge, to any person...\n",
        encoding="utf-8",
    )
    findings = _rules(_context(root), DocumentationAnalyzer())
    assert "RL-DOC-004" in findings


def test_matching_license_declaration_is_clean(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package.json").write_text(
        json.dumps({"name": "demo", "license": "MIT"}), encoding="utf-8"
    )
    (root / "LICENSE").write_text(
        "MIT License\nPermission is hereby granted...\n", encoding="utf-8"
    )
    assert _rules(_context(root), DocumentationAnalyzer()) == {}


def test_unknown_spdx_identifier_is_not_flagged(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package.json").write_text(
        json.dumps({"name": "demo", "license": "SEE LICENSE IN LICENSE"}), encoding="utf-8"
    )
    (root / "LICENSE").write_text("Custom proprietary terms.\n", encoding="utf-8")
    assert _rules(_context(root), DocumentationAnalyzer()) == {}


def test_malformed_manifests_do_not_crash_documentation_analyzer(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    (root / "package.json").write_text("{broken", encoding="utf-8")
    (root / "README.md").write_text("# Demo\n", encoding="utf-8")
    assert _rules(_context(root), DocumentationAnalyzer()) == {}


# --------------------------------------------------------------------------------------
# Testing hygiene
# --------------------------------------------------------------------------------------


def test_missing_python_tests_are_reported(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo(include_tests=False)
    findings = _rules(_context(repo), HygieneAnalyzer())
    assert "RL-TEST-001" in findings
    assert findings["RL-TEST-001"].severity.value == "medium"  # type: ignore[attr-defined]


def test_missing_jsts_tests_are_reported(make_jsts_repo: Callable[..., Path]) -> None:
    repo = make_jsts_repo(include_tests=False)
    findings = _rules(_context(repo), HygieneAnalyzer())
    assert "RL-TEST-002" in findings


def test_healthy_repositories_have_no_testing_findings(
    make_python_repo: Callable[..., Path], make_jsts_repo: Callable[..., Path]
) -> None:
    assert _rules(_context(make_python_repo()), HygieneAnalyzer()) == {}
    assert _rules(_context(make_jsts_repo()), HygieneAnalyzer()) == {}


def test_python_tests_without_runner_configuration(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "sample"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    findings = _rules(_context(repo), HygieneAnalyzer())
    assert "RL-TEST-003" in findings


def test_jsts_tests_without_test_script(make_jsts_repo: Callable[..., Path]) -> None:
    repo = make_jsts_repo()
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "sample-ts",
                "version": "1.0.0",
                "license": "MIT",
                "devDependencies": {"typescript": "^5.6.0"},
            }
        ),
        encoding="utf-8",
    )
    findings = _rules(_context(repo), HygieneAnalyzer())
    assert "RL-TEST-003" in findings


def test_placeholder_test_script_is_not_a_runner(make_jsts_repo: Callable[..., Path]) -> None:
    repo = make_jsts_repo()
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "sample-ts",
                "version": "1.0.0",
                "license": "MIT",
                "scripts": {"test": 'echo "Error: no test specified" && exit 1'},
            }
        ),
        encoding="utf-8",
    )
    findings = _rules(_context(repo), HygieneAnalyzer())
    assert "RL-TEST-003" in findings


def test_declared_coverage_tooling_without_configuration(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / "pyproject.toml").write_text(
        "[project]\n"
        'name = "sample"\n'
        'version = "0.1.0"\n'
        "\n[dependency-groups]\n"
        'dev = ["pytest>=8", "pytest-cov>=5"]\n'
        "\n[tool.pytest.ini_options]\n"
        'testpaths = ["tests"]\n',
        encoding="utf-8",
    )
    findings = _rules(_context(repo), HygieneAnalyzer())
    assert "RL-TEST-004" in findings
    assert findings["RL-TEST-004"].severity.value == "info"  # type: ignore[attr-defined]

    (repo / ".coveragerc").write_text("[run]\nbranch = True\n", encoding="utf-8")
    assert "RL-TEST-004" not in _rules(_context(repo), HygieneAnalyzer())


def test_undeclared_pytest_import_is_reported(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / "tests" / "test_core.py").write_text(
        "import pytest\n\n\ndef test_ok():\n    assert True\n", encoding="utf-8"
    )
    findings = _rules(_context(repo), HygieneAnalyzer())
    assert "RL-TEST-005" in findings
    assert findings["RL-TEST-005"].location.path == "tests/test_core.py"  # type: ignore[attr-defined]


def test_declared_pytest_suppresses_undeclared_import_warning(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo()
    (repo / "pyproject.toml").write_text(
        "[project]\n"
        'name = "sample"\n'
        'version = "0.1.0"\n'
        "\n[dependency-groups]\n"
        'dev = ["pytest>=8"]\n'
        "\n[tool.pytest.ini_options]\n"
        'testpaths = ["tests"]\n',
        encoding="utf-8",
    )
    (repo / "tests" / "test_core.py").write_text(
        "import pytest\n\n\ndef test_ok():\n    assert True\n", encoding="utf-8"
    )
    assert "RL-TEST-005" not in _rules(_context(repo), HygieneAnalyzer())


def test_ignored_test_files_are_not_counted(
    make_python_repo: Callable[..., Path],
) -> None:
    repo = make_python_repo(include_tests=False)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_core.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8"
    )
    (repo / ".gitignore").write_text("tests/\n__pycache__/\n.venv/\n.env\n", encoding="utf-8")
    findings = _rules(_context(repo), HygieneAnalyzer())
    assert "RL-TEST-001" in findings


def test_conflicting_license_declarations_are_reported(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nlicense = "Apache-2.0"\n', encoding="utf-8"
    )
    (root / "package.json").write_text(
        json.dumps({"name": "demo", "license": "MIT"}), encoding="utf-8"
    )
    (root / "LICENSE").write_text(
        "MIT License\nPermission is hereby granted...\n", encoding="utf-8"
    )

    findings = _rules(_context(root), DocumentationAnalyzer())
    assert "RL-DOC-005" in findings
    evidence = findings["RL-DOC-005"].evidence  # type: ignore[attr-defined]
    assert "Apache-2.0" in evidence
    assert "MIT" in evidence


def test_agreeing_license_declarations_are_clean(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nlicense = "MIT"\n', encoding="utf-8"
    )
    (root / "package.json").write_text(
        json.dumps({"name": "demo", "license": "MIT"}), encoding="utf-8"
    )
    (root / "LICENSE").write_text(
        "MIT License\nPermission is hereby granted...\n", encoding="utf-8"
    )
    assert _rules(_context(root), DocumentationAnalyzer()) == {}
