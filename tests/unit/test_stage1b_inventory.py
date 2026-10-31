"""Regressions for dependency inventory, npm depth, and pnpm coverage."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from repolens.analyzers.advisories import OsvVulnerabilityAnalyzer
from repolens.analyzers.base import AnalyzerExecutionError
from repolens.analyzers.dependencies import DependencyAnalyzer
from repolens.cli import determine_exit_code
from repolens.config import ScanConfig
from repolens.dependencies import Ecosystem, build_dependency_inventory
from repolens.discovery import RepositoryContext, discover_repository
from repolens.engine import ScanEngine
from repolens.exceptions import DiscoveryError
from repolens.json_output import build_json_document
from repolens.models import AnalyzerStatus, Confidence, Severity
from repolens.osv import OsvPackage, OsvVulnerability


def _write(root: Path, path: str, text: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _context(root: Path, config: ScanConfig | None = None) -> RepositoryContext:
    return discover_repository(root, config or ScanConfig())


def _inputs(root: Path, count: int) -> None:
    for index in range(count):
        _write(root, f"inputs/{index:03}/requirements.txt", "")


class _Client:
    def __init__(self, vulnerability: OsvVulnerability | None = None) -> None:
        self.packages: list[OsvPackage] = []
        self.vulnerability = vulnerability

    def query(self, packages: Sequence[OsvPackage]) -> list[OsvVulnerability]:
        self.packages.extend(packages)
        return [self.vulnerability] if self.vulnerability is not None else []


def _vulnerability(name: str, ecosystem: str = "npm") -> OsvVulnerability:
    return OsvVulnerability(
        vuln_id="GHSA-stage1b",
        package=OsvPackage(name=name, version="1.0.0", ecosystem=ecosystem),
        summary="A confirmed advisory.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )


@pytest.mark.parametrize(("count", "incomplete"), [(79, False), (80, False), (81, True)])
def test_manifest_limit_detects_only_actual_omissions(
    tmp_path: Path, count: int, incomplete: bool
) -> None:
    _inputs(tmp_path, count)
    context = _context(tmp_path)
    inventory = build_dependency_inventory(context)
    assert len(inventory.python_manifest_paths) == min(count, 80)
    assert bool(inventory.gaps) is incomplete
    if incomplete:
        assert inventory.gaps[0].path == "inputs/080/requirements.txt"
        assert "80-read limit" in inventory.gaps[0].reason
    analyzer = DependencyAnalyzer()
    report = ScanEngine(analyzers=[analyzer]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status == (
        AnalyzerStatus.FAILED if incomplete else AnalyzerStatus.COMPLETED
    )
    assert determine_exit_code(report, Severity.CRITICAL) == (3 if incomplete else 0)


def test_ignored_unsupported_sensitive_oversized_and_irrelevant_inputs_are_not_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _inputs(tmp_path, 80)
    _write(tmp_path, ".gitignore", "zignored/\n")
    _write(tmp_path, "zignored/requirements.txt", "pytest==8.0.0\n")
    _write(tmp_path, "zsensitive/requirements.txt", "pytest==8.0.0\n")
    _write(tmp_path, "zoversized/requirements.txt", "x" * 1025)
    _write(tmp_path, "zunsupported/bun.lockb", "not safe text")
    _write(tmp_path, "zother/file.txt", "not a manifest")
    context = _context(tmp_path, ScanConfig(max_file_size_bytes=1024))
    # Exercise the policy even if a recognized filename is classified sensitive by a
    # future discovery rule or supplied by a caller constructing a context.
    context.files = tuple(
        replace(item, is_sensitive=True) if item.path.startswith("zsensitive/") else item
        for item in context.files
    )
    context.files_by_path = {item.path: item for item in context.files}
    original = context.read_text

    def guarded(path: str) -> str:
        assert not path.startswith(("zignored/", "zsensitive/", "zoversized/", "zunsupported/"))
        return original(path)

    monkeypatch.setattr(context, "read_text", guarded)
    inventory = build_dependency_inventory(context)
    assert len(inventory.python_manifest_paths) == 80
    assert inventory.gaps == ()
    assert [problem.path for problem in inventory.problems] == ["zunsupported/bun.lockb"]


@pytest.mark.parametrize("bad_path", ["a/requirements.txt", "z/requirements.txt"])
def test_unreadable_manifests_before_or_after_successful_reads_are_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_path: str
) -> None:
    _write(tmp_path, "m/requirements.txt", "requests==1.0.0\n")
    _write(tmp_path, bad_path, "pytest==8.0.0\n")
    original = RepositoryContext.read_text

    def fail_selected(context: RepositoryContext, path: str) -> str:
        if path == bad_path:
            raise DiscoveryError("unreadable")
        return original(context, path)

    monkeypatch.setattr(RepositoryContext, "read_text", fail_selected)
    inventory = build_dependency_inventory(_context(tmp_path))
    assert [gap.path for gap in inventory.gaps] == [bad_path]
    assert not inventory.declarations_complete(Ecosystem.PYPI)
    assert [(p.name, p.version) for p in inventory.locked] == [("requests", "1.0.0")]
    report = ScanEngine(analyzers=[DependencyAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert determine_exit_code(report, Severity.CRITICAL) == 3


def test_unreadable_after_eighty_reads_is_not_read_past_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _inputs(tmp_path, 80)
    _write(tmp_path, "z/requirements.txt", "pytest==8.0.0\n")
    context = _context(tmp_path)
    original = context.read_text

    def guarded(path: str) -> str:
        assert path != "z/requirements.txt"
        return original(path)

    monkeypatch.setattr(context, "read_text", guarded)
    inventory = build_dependency_inventory(context)
    assert len(inventory.gaps) == 1
    assert "80-read limit" in inventory.gaps[0].reason


def test_omitted_python_lockfile_suppresses_unproven_missing_lock_finding(tmp_path: Path) -> None:
    _write(tmp_path, "a/pyproject.toml", '[project]\ndependencies = ["requests>=2"]\n')
    _inputs(tmp_path, 79)
    _write(tmp_path, "z/poetry.lock", '[[package]]\nname = "requests"\nversion = "2.0"\n')
    report = ScanEngine(analyzers=[DependencyAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-DEP-005" not in {f.rule_id for f in report.findings}


def test_malformed_lockfile_alone_is_applicable_and_osv_does_not_claim_clean(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "package-lock.json", "{broken")
    client = _Client()
    dep = DependencyAnalyzer()
    osv = OsvVulnerabilityAnalyzer(client_factory=lambda _config: client)
    report = ScanEngine(config=ScanConfig(enable_network_checks=True), analyzers=[dep, osv]).scan(
        tmp_path
    )
    assert [outcome.status for outcome in report.analyzer_outcomes] == [
        AnalyzerStatus.FAILED,
        AnalyzerStatus.FAILED,
    ]
    assert {finding.rule_id for finding in report.findings} == {"RL-DEP-001"}
    assert not client.packages
    assert determine_exit_code(report, Severity.MEDIUM) == 1
    assert determine_exit_code(report, Severity.CRITICAL) == 3
    doc = build_json_document(report, exit_code=1, min_severity=Severity.MEDIUM)
    assert doc["schema_version"] == "1.1.0"
    assert doc["result"]["status"] == "findings_and_incomplete"
    assert doc["result"]["incomplete_reasons"] == ["analyzer_failed"]
    assert all(
        not o.coverage_truncated and not o.coverage_incomplete for o in report.analyzer_outcomes
    )

    disabled = ScanEngine(analyzers=[osv]).scan(tmp_path)
    assert disabled.analyzer_outcomes[0].status is AnalyzerStatus.SKIPPED
    assert "disabled" in (disabled.analyzer_outcomes[0].message or "").lower()
    assert not client.packages


def test_inventory_gap_retains_osv_advisory_and_honors_fail_fast(tmp_path: Path) -> None:
    _write(tmp_path, "a/requirements.txt", "requests==1.0.0\n")
    _inputs(tmp_path, 79)
    _write(tmp_path, "z/requirements.txt", "other==2.0.0\n")
    client = _Client(_vulnerability("requests", "PyPI"))
    osv = OsvVulnerabilityAnalyzer(client_factory=lambda _config: client)
    report = ScanEngine(config=ScanConfig(enable_network_checks=True), analyzers=[osv]).scan(
        tmp_path
    )
    assert [p.name for p in client.packages] == ["requests"]
    assert [f.rule_id for f in report.findings] == ["OSV-GHSA-stage1b"]
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert determine_exit_code(report) == 1
    with pytest.raises(AnalyzerExecutionError, match="Dependency inventory incomplete"):
        ScanEngine(config=ScanConfig(fail_fast=True), analyzers=[DependencyAnalyzer()]).scan(
            tmp_path
        )


def _npm_tree(levels: int, *, empty_child: bool = False) -> str:
    nested: dict[str, object] = {}
    for level in reversed(range(levels)):
        entry: dict[str, object] = {"version": "1.0.0"}
        if nested or (empty_child and level == levels - 1):
            entry["dependencies"] = nested
        nested = {f"p{level}": entry}
    return json.dumps({"lockfileVersion": 1, "dependencies": nested})


@pytest.mark.parametrize(
    ("levels", "empty_child", "gap"), [(13, False, False), (13, True, False), (14, False, True)]
)
def test_npm_depth_boundary_tracks_only_omitted_packages(
    tmp_path: Path, levels: int, empty_child: bool, gap: bool
) -> None:
    _write(tmp_path, "package-lock.json", _npm_tree(levels, empty_child=empty_child))
    inventory = build_dependency_inventory(_context(tmp_path))
    assert len(inventory.locked) == min(levels, 13)
    assert inventory.lockfiles[0].complete is not gap
    assert bool(inventory.gaps) is gap
    assert {p.name for p in inventory.locked} == {f"p{i}" for i in range(min(levels, 13))}


def test_npm_depth_gap_retains_packages_and_osv_findings_without_false_mismatch(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "package-lock.json", _npm_tree(14))
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"p13": "1.0.0"}}))
    client = _Client(_vulnerability("p0"))
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[
            DependencyAnalyzer(),
            OsvVulnerabilityAnalyzer(client_factory=lambda _cfg: client),
        ],
    ).scan(tmp_path)
    assert [o.status for o in report.analyzer_outcomes] == [AnalyzerStatus.FAILED] * 2
    assert len(client.packages) == 13
    assert "RL-DEP-003" not in {f.rule_id for f in report.findings}
    assert "OSV-GHSA-stage1b" in {f.rule_id for f in report.findings}
    assert determine_exit_code(report) == 1


@pytest.mark.parametrize("version", [2, 3])
def test_npm_flat_lockfiles_do_not_use_tree_depth_budget(tmp_path: Path, version: int) -> None:
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps(
            {"lockfileVersion": version, "packages": {"node_modules/foo": {"version": "1.0.0"}}}
        ),
    )
    inventory = build_dependency_inventory(_context(tmp_path))
    assert inventory.gaps == ()
    assert inventory.lockfiles[0].complete
    assert [(p.name, p.version) for p in inventory.locked] == [("foo", "1.0.0")]


def test_deeply_nested_json_does_not_crash_the_scan(tmp_path: Path) -> None:
    payload = '{"nested":' * 1100 + "0" + "}" * 1100
    _write(tmp_path, "package-lock.json", payload)
    report = ScanEngine(analyzers=[DependencyAnalyzer()]).scan(tmp_path)
    # CPython's JSON nesting limit differs by version and platform. If it can
    # parse this object, it contains no dependency entries and is not applicable.
    if report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED:
        assert [f.rule_id for f in report.findings] == ["RL-DEP-001"]
    else:
        assert report.analyzer_outcomes[0].status is AnalyzerStatus.SKIPPED
        assert report.findings == []


def test_npm_json_recursion_error_is_reported_and_retains_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path, "package-lock.json", "{}")
    context = _context(tmp_path)

    def too_deep(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("unsafe nesting")

    monkeypatch.setattr("repolens.dependencies.json.loads", too_deep)
    analyzer = DependencyAnalyzer()
    assert analyzer.is_applicable(context)
    findings = analyzer.analyze(context, ScanConfig())
    assert [f.rule_id for f in findings] == ["RL-DEP-001"]
    assert "could not be fully parsed" in (analyzer.reporting_failure() or "")


@pytest.mark.parametrize(
    "key",
    [
        "'/@scope/pkg/1.0.0_peer@2.0.0'",  # pnpm v5
        "'/@scope/pkg@1.0.0(peer@2.0.0)'",  # pnpm v6
        "'@scope/pkg@1.0.0'",  # pnpm v9
        "'@scope/pkg@1.0.0(peer@2.0.0)(other@3.0.0)'",  # v9 snapshot
    ],
)
def test_pnpm_versions_scoped_quotes_and_peer_suffixes(tmp_path: Path, key: str) -> None:
    _write(
        tmp_path,
        "pnpm-lock.yaml",
        f"lockfileVersion: '9.0'\npackages:\n  {key}:\n    resolution: {{}}\n",
    )
    inventory = build_dependency_inventory(_context(tmp_path))
    assert [(p.name, p.version) for p in inventory.locked] == [("@scope/pkg", "1.0.0")]
    assert inventory.gaps == ()
    # This flag is about consistency, not whether coordinates were omitted.
    assert inventory.lockfiles[0].complete is False


@pytest.mark.parametrize("section", ["packages:\n", "packages: {}\n", "packages: # empty\n"])
def test_empty_pnpm_package_sections_are_not_gaps(tmp_path: Path, section: str) -> None:
    _write(tmp_path, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n" + section)
    inventory = build_dependency_inventory(_context(tmp_path))
    assert inventory.gaps == ()
    assert inventory.locked == ()
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True),
        analyzers=[OsvVulnerabilityAnalyzer(client_factory=lambda _cfg: _Client())],
    ).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.SKIPPED


@pytest.mark.parametrize("known", [False, True])
def test_pnpm_unknown_entries_propagate_with_zero_or_some_known_coordinates(
    tmp_path: Path, known: bool
) -> None:
    known_entry = "  react@1.0.0:\n    resolution: {}\n" if known else ""
    _write(
        tmp_path,
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n"
        + known_entry
        + "  'unknown@workspace:*':\n    resolution: {}\n",
    )
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"missing": "1.0.0"}}))
    client = _Client(_vulnerability("react"))
    osv = OsvVulnerabilityAnalyzer(client_factory=lambda _cfg: client)
    report = ScanEngine(
        config=ScanConfig(enable_network_checks=True), analyzers=[DependencyAnalyzer(), osv]
    ).scan(tmp_path)
    assert [o.status for o in report.analyzer_outcomes] == [AnalyzerStatus.FAILED] * 2
    assert len(client.packages) == int(known)
    assert "RL-DEP-003" not in {f.rule_id for f in report.findings}
    assert ("OSV-GHSA-stage1b" in {f.rule_id for f in report.findings}) is known
    assert determine_exit_code(report, Severity.HIGH) == (1 if known else 3)
    disabled = ScanEngine(analyzers=[osv]).scan(tmp_path)
    assert disabled.analyzer_outcomes[0].status is AnalyzerStatus.SKIPPED
    assert "disabled" in (disabled.analyzer_outcomes[0].message or "").lower()


def test_partial_pnpm_and_partially_pinned_requirements_are_distinct(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "requests>=2\nflask==1.0.0\n")
    _write(tmp_path, "pnpm-lock.yaml", "packages:\n  react@1.0.0:\n    resolution: {}\n")
    inventory = build_dependency_inventory(_context(tmp_path))
    assert all(not lock.complete for lock in inventory.lockfiles)
    assert inventory.gaps == ()


def test_dependency_and_osv_reporting_state_resets_between_scans(tmp_path: Path) -> None:
    _inputs(tmp_path, 81)
    client = _Client()
    dep = DependencyAnalyzer()
    osv = OsvVulnerabilityAnalyzer(client_factory=lambda _cfg: client)
    engine = ScanEngine(config=ScanConfig(enable_network_checks=True), analyzers=[dep, osv])
    first = engine.scan(tmp_path)
    assert [o.status for o in first.analyzer_outcomes] == [AnalyzerStatus.FAILED] * 2
    (tmp_path / "inputs/080/requirements.txt").unlink()
    second = engine.scan(tmp_path)
    assert second.analyzer_outcomes[0].status is AnalyzerStatus.COMPLETED
    assert second.analyzer_outcomes[1].status is AnalyzerStatus.SKIPPED
    assert dep.reporting_failure() is None


@pytest.mark.parametrize("content", ["[]", '{"number": ' + "9" * 5000 + "}"])
def test_invalid_npm_lockfile_shapes_and_unsafe_numbers_are_incomplete(
    tmp_path: Path, content: str
) -> None:
    _write(tmp_path, "package-lock.json", content)
    report = ScanEngine(analyzers=[DependencyAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert [f.rule_id for f in report.findings] == ["RL-DEP-001"]


def test_pnpm_variable_indentation_and_v9_snapshot_duplicates(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\n"
        "packages :\n"
        "    '@scope/pkg@1.0.0':\n"
        "      resolution: {}\n"
        "snapshots:\n"
        "    '@scope/pkg@1.0.0(peer@2.0.0)':\n"
        "      dependencies: {}\n",
    )
    inventory = build_dependency_inventory(_context(tmp_path))
    assert inventory.gaps == ()
    assert [(item.name, item.version) for item in inventory.locked] == [("@scope/pkg", "1.0.0")]


def test_pnpm_inconsistent_indentation_cannot_silently_hide_entries(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pnpm-lock.yaml",
        "packages:\n    foo@1.0.0:\n      resolution: {}\n  bar@2.0.0:\n    resolution: {}\n",
    )
    inventory = build_dependency_inventory(_context(tmp_path))
    assert inventory.gaps
    assert {(p.name, p.version) for p in inventory.locked} == {("foo", "1.0.0"), ("bar", "2.0.0")}


def test_incomplete_sibling_lockfile_suppresses_absence_from_other_lockfile(tmp_path: Path) -> None:
    _write(tmp_path, "package-lock.json", _npm_tree(14))
    _write(tmp_path, "yarn.lock", '"other@1.0.0":\n  version "1.0.0"\n')
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"p13": "1.0.0"}}))
    report = ScanEngine(analyzers=[DependencyAnalyzer()]).scan(tmp_path)
    assert report.analyzer_outcomes[0].status is AnalyzerStatus.FAILED
    assert "RL-DEP-003" not in {f.rule_id for f in report.findings}


def test_manifest_removed_after_discovery_is_an_inventory_gap(tmp_path: Path) -> None:
    _write(tmp_path, "a/requirements.txt", "requests==1.0.0\n")
    _write(tmp_path, "z/requirements.txt", "pytest==8.0.0\n")
    context = _context(tmp_path)
    (tmp_path / "z/requirements.txt").unlink()
    inventory = build_dependency_inventory(context)
    assert [gap.path for gap in inventory.gaps] == ["z/requirements.txt"]
    assert [(p.name, p.version) for p in inventory.locked] == [("requests", "1.0.0")]
    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(context, ScanConfig())
    assert findings == []
    assert "could not be read" in (analyzer.reporting_failure() or "")


def test_pnpm_unbalanced_peer_suffix_is_an_inventory_gap(tmp_path: Path) -> None:
    _write(
        tmp_path, "pnpm-lock.yaml", "packages:\n  'broken@1.0.0(peer@2.0.0':\n    resolution: {}\n"
    )
    inventory = build_dependency_inventory(_context(tmp_path))
    assert inventory.gaps
    assert inventory.locked == ()
