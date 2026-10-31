"""Offline dependency-manifest and lockfile hygiene analyzer.

All checks in this analyzer are purely static and local: manifests are parsed with
standard-library parsers and no package resolution, installation, or network access
occurs. Known-vulnerability lookups live in ``repolens.analyzers.advisories`` and are
opt-in.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from repolens import __version__
from repolens.analyzers.base import Analyzer
from repolens.config import ScanConfig
from repolens.dependencies import (
    DeclaredDependency,
    DependencyInventory,
    DependencyProblemKind,
    Ecosystem,
    build_dependency_inventory,
)
from repolens.discovery import RepositoryContext
from repolens.models import (
    Category,
    Confidence,
    Finding,
    FindingLocation,
    FindingSource,
    Severity,
    SourceKind,
)

_SOURCE = FindingSource(
    kind=SourceKind.DETERMINISTIC,
    tool="repolens-dependencies",
    tool_version=__version__,
)

_SEMVER_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+][0-9A-Za-z.-]+)?$")


def _version_parts(version: str) -> tuple[int, int, int] | None:
    match = _SEMVER_RE.match(version.strip())
    if match is None:
        return None
    return (
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
    )


def npm_spec_satisfied(version: str, specifier: str) -> bool | None:
    """Return True/False when a simple npm semver constraint can be evaluated, else None.

    Complex constraints (``||``, ranges, prerelease tags, ``npm:`` aliases) deliberately
    return None so RepoLens never reports an inconsistency it cannot prove.
    """
    spec = specifier.strip()
    if not spec or spec in {"*", "x", "X", "latest"}:
        return None
    unsupported_tokens = ("||", " - ", ">=", "<=", ">", "<", " ", "npm:", "workspace:")
    if any(token in spec for token in unsupported_tokens):
        return None
    if spec.endswith((".x", ".X", ".*")) or "*" in spec:
        return None

    actual = _version_parts(version)
    if actual is None:
        return None

    operator = ""
    remainder = spec
    if spec[0] in "^~=":
        operator = spec[0]
        remainder = spec[1:].strip()

    expected = _version_parts(remainder)
    if expected is None:
        return None

    if operator == "^":
        if expected[0] > 0:
            return actual[0] == expected[0] and actual >= expected
        if expected[1] > 0:
            return actual[0] == 0 and actual[1] == expected[1] and actual >= expected
        # `^0.0.z` permits only the exact patch version.
        return actual == expected
    if operator == "~":
        return actual[0] == expected[0] and actual[1] == expected[1] and actual >= expected
    return actual == expected


class DependencyAnalyzer(Analyzer):
    """Static dependency manifest/lockfile hygiene checks (no network access)."""

    def __init__(self) -> None:
        self._message: str | None = None

    @property
    def name(self) -> str:
        return "dependency-manifests"

    def is_applicable(self, context: RepositoryContext) -> bool:
        inventory = build_dependency_inventory(context)
        return bool(
            inventory.python_manifest_paths
            or inventory.npm_manifest_paths
            or inventory.problems
            or inventory.gaps
        )

    def completion_message(self) -> str | None:
        return self._message

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        self._reset_reporting()
        self._message = None
        inventory = build_dependency_inventory(context)
        if message := inventory.gap_message():
            self._mark_reporting_failure(message)
        findings: list[Finding] = []

        findings.extend(self._report_parse_problems(inventory))
        findings.extend(self._check_npm_lockfile_consistency(inventory))
        findings.extend(self._check_python_pins(inventory))
        findings.extend(self._check_python_lockfile(inventory))

        declared = len(inventory.declared)
        locked = len({(p.ecosystem, p.name, p.version) for p in inventory.locked})
        self._message = (
            f"Parsed {declared} declared dependenc(y/ies) and {locked} locked package version(s)."
        )
        return self._limit_findings(findings, config.max_findings_per_analyzer)

    # -- parse problems -------------------------------------------------------------

    def _report_parse_problems(self, inventory: DependencyInventory) -> list[Finding]:
        findings: list[Finding] = []
        for problem in inventory.problems:
            if problem.kind is DependencyProblemKind.MALFORMED_LOCKFILE:
                findings.append(
                    Finding(
                        rule_id="RL-DEP-001",
                        category=Category.DEPENDENCIES,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"Malformed dependency lockfile: {PurePosixPath(problem.path).name}",
                        location=FindingLocation(path=problem.path, start_line=problem.line),
                        evidence=problem.message,
                        explanation=(
                            "A damaged lockfile silently disables reproducible installs and "
                            "prevents reliable dependency auditing."
                        ),
                        recommendation=(
                            f"Regenerate `{problem.path}` with your package manager and commit "
                            "the result. Do not hand-edit lockfiles."
                        ),
                        verification=(
                            f"Parse `{problem.path}` with its native tool and confirm it succeeds."
                        ),
                        source=_SOURCE,
                    )
                )
            elif problem.kind is DependencyProblemKind.MALFORMED_MANIFEST:
                # Root manifest syntax has an existing structure-analyzer finding.
                if problem.path in {"pyproject.toml", "package.json"}:
                    continue
                findings.append(
                    Finding(
                        rule_id="RL-DEP-008",
                        category=Category.DEPENDENCIES,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"Malformed dependency manifest: {PurePosixPath(problem.path).name}",
                        location=FindingLocation(path=problem.path),
                        evidence=problem.message,
                        explanation=(
                            "A nested manifest that cannot be parsed prevents dependency "
                            "enumeration for that workspace or package."
                        ),
                        recommendation=f"Fix the syntax of `{problem.path}`.",
                        verification=f"Parse `{problem.path}` with its native parser.",
                        source=_SOURCE,
                    )
                )
            elif problem.kind is DependencyProblemKind.INVALID_REQUIREMENT:
                findings.append(
                    Finding(
                        rule_id="RL-DEP-002",
                        category=Category.DEPENDENCIES,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title="Invalid Python dependency requirement",
                        location=FindingLocation(path=problem.path, start_line=problem.line),
                        evidence=problem.message,
                        explanation=(
                            "A requirement that does not follow PEP 508 cannot be installed and "
                            "breaks dependency resolution for the whole file."
                        ),
                        recommendation=(
                            "Correct the requirement to a valid PEP 508 specifier such as "
                            "`package>=1.2,<2`."
                        ),
                        verification=f"Run `pip install --dry-run -r {problem.path}` in a sandbox.",
                        source=_SOURCE,
                    )
                )
            elif problem.kind is DependencyProblemKind.UNSUPPORTED_LOCKFILE:
                findings.append(
                    Finding(
                        rule_id="RL-DEP-007",
                        category=Category.DEPENDENCIES,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        title=f"Unsupported lockfile format: {PurePosixPath(problem.path).name}",
                        location=FindingLocation(path=problem.path),
                        evidence=problem.message,
                        explanation=(
                            "RepoLens cannot read every lockfile format, so offline consistency "
                            "checks and optional vulnerability lookups may be incomplete."
                        ),
                        recommendation=(
                            "Export dependency metadata in a supported format (for example "
                            "`package-lock.json` or `yarn.lock`) if you want full audit coverage."
                        ),
                        verification=f"Confirm `{problem.path}` is intentionally committed.",
                        source=_SOURCE,
                    )
                )
        return findings

    # -- JavaScript / TypeScript ----------------------------------------------------

    def _check_npm_lockfile_consistency(self, inventory: DependencyInventory) -> list[Finding]:
        findings: list[Finding] = []
        for manifest_path in inventory.npm_manifest_paths:
            directory = _parent_dir(manifest_path)
            lockfiles = inventory.lockfiles_for_dir(Ecosystem.NPM, directory)
            complete_lockfiles = [lockfile for lockfile in lockfiles if lockfile.complete]
            if not complete_lockfiles:
                # Missing lockfiles are reported by the structure analyzer; unsupported
                # lockfile formats are reported via RL-DEP-007.
                continue

            locked_by_name: dict[str, list[str]] = {}
            for package in inventory.locked:
                if package.ecosystem is not Ecosystem.NPM:
                    continue
                complete_paths = {lockfile.path for lockfile in complete_lockfiles}
                if package.source_path not in complete_paths:
                    continue
                locked_by_name.setdefault(package.name.lower(), []).append(package.version)

            declared = [
                dep
                for dep in inventory.declared_for(Ecosystem.NPM)
                if dep.source_path == manifest_path
            ]
            lockfile_names = ", ".join(sorted(lockfile.path for lockfile in complete_lockfiles))

            for dependency in declared:
                locked_versions = locked_by_name.get(dependency.key)
                if not locked_versions:
                    if not inventory.lockfiles_complete(Ecosystem.NPM, directory):
                        continue
                    findings.append(
                        Finding(
                            rule_id="RL-DEP-003",
                            category=Category.DEPENDENCIES,
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            title=f"Dependency declared but not locked: {dependency.name}",
                            location=FindingLocation(path=manifest_path),
                            evidence=(
                                f"`{dependency.name}` is declared in {manifest_path} but no "
                                f"matching entry exists in {lockfile_names}."
                            ),
                            explanation=(
                                "A manifest/lockfile mismatch means CI installs a different "
                                "dependency tree than developers reproduce locally."
                            ),
                            recommendation=(
                                "Run your package manager's install command with the lockfile "
                                "and commit the updated lockfile, or remove the unused declaration."
                            ),
                            verification=(
                                f"Confirm `{dependency.name}` appears in {lockfile_names} and in "
                                "the resolved dependency tree."
                            ),
                            source=_SOURCE,
                        )
                    )
                    continue

                mismatched = self._first_mismatch(dependency, locked_versions)
                if mismatched is None:
                    continue
                findings.append(
                    Finding(
                        rule_id="RL-DEP-004",
                        category=Category.DEPENDENCIES,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        title=f"Locked version outside declared range: {dependency.name}",
                        location=FindingLocation(path=manifest_path),
                        evidence=(
                            f"`{dependency.name}@{dependency.specifier}` is declared, but "
                            f"{lockfile_names} resolves {mismatched}."
                        ),
                        explanation=(
                            "When the lockfile no longer satisfies the declared range, installs "
                            "can silently drift between environments and CI."
                        ),
                        recommendation=(
                            "Regenerate the lockfile, or relax the declared range if the locked "
                            "version is intentional."
                        ),
                        verification=(
                            f"Run your package manager's dependency check for `{dependency.name}`."
                        ),
                        source=_SOURCE,
                    )
                )
        return findings

    @staticmethod
    def _first_mismatch(dependency: DeclaredDependency, locked_versions: list[str]) -> str | None:
        if not dependency.specifier:
            return None
        for version in locked_versions:
            satisfied = npm_spec_satisfied(version, dependency.specifier)
            if satisfied is None:
                return None
            if not satisfied:
                return version
        return None

    # -- Python ---------------------------------------------------------------------

    def _check_python_pins(self, inventory: DependencyInventory) -> list[Finding]:
        pinned: dict[str, dict[str, list[str]]] = {}
        display: dict[str, str] = {}
        for dependency in inventory.declared_for(Ecosystem.PYPI):
            exact = dependency.exact_version
            if exact is None:
                continue
            pinned.setdefault(dependency.key, {}).setdefault(exact, []).append(
                f"{dependency.source_path}"
            )
            display.setdefault(dependency.key, dependency.name)

        findings: list[Finding] = []
        for key, versions in sorted(pinned.items()):
            if len(versions) < 2:
                continue
            rendered = "; ".join(
                f"{version} ({', '.join(sorted(set(paths)))})"
                for version, paths in sorted(versions.items())
            )
            source_path = sorted({path for paths in versions.values() for path in paths})[0]
            findings.append(
                Finding(
                    rule_id="RL-DEP-006",
                    category=Category.DEPENDENCIES,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Conflicting pinned versions for {display.get(key, key)}",
                    location=FindingLocation(path=source_path),
                    evidence=f"Conflicting exact pins: {rendered}",
                    explanation=(
                        "Multiple exact pins for the same Python distribution guarantee that "
                        "at least one environment installs the wrong version."
                    ),
                    recommendation="Align the pins across manifests or remove the redundant pin.",
                    verification=(
                        f"Search the repository for pin declarations of `{display.get(key, key)}`."
                    ),
                    source=_SOURCE,
                )
            )
        return findings

    def _check_python_lockfile(self, inventory: DependencyInventory) -> list[Finding]:
        runtime = [dep for dep in inventory.declared_for(Ecosystem.PYPI) if not dep.dev]
        if (
            not runtime
            or inventory.has_python_lockfile()
            or not inventory.lockfiles_complete(Ecosystem.PYPI)
        ):
            return []

        unpinned = [dep for dep in runtime if dep.exact_version is None]
        if not unpinned:
            return []

        manifest = sorted({dep.source_path for dep in unpinned})[0]
        sample = ", ".join(sorted({dep.name for dep in unpinned})[:5])
        return [
            Finding(
                rule_id="RL-DEP-005",
                category=Category.DEPENDENCIES,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="Python runtime dependencies are not pinned or locked",
                location=FindingLocation(path=manifest),
                evidence=f"{len(unpinned)} unpinned runtime dependency range(s), e.g. {sample}.",
                explanation=(
                    "Without a lockfile or pinned requirements, installs resolve to different "
                    "versions over time, which makes vulnerability data and bug reports "
                    "non-reproducible. This is advisory for libraries that intentionally do not "
                    "commit lockfiles."
                ),
                recommendation=(
                    "Commit a lockfile (`uv.lock`, `poetry.lock`, `pdm.lock`, or `Pipfile.lock`) "
                    "for applications, or pin exact versions for deployable environments."
                ),
                verification="Confirm a lockfile is tracked or that ranges are intentionally open.",
                source=_SOURCE,
            )
        ]


def _parent_dir(path: str) -> str:
    parent = PurePosixPath(path).parent
    return "" if parent == PurePosixPath(".") else parent.as_posix()


__all__ = ["DependencyAnalyzer", "npm_spec_satisfied"]
