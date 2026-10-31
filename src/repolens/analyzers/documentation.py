"""Documentation consistency analyzer.

Complements the structure analyzer's missing/empty README checks with cross-references
between manifests and documentation files. Findings are deliberately conservative: an
optional file being absent is not treated as a defect, and severity stays low unless the
inconsistency breaks packaging metadata.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import PurePosixPath
from typing import Any, cast

from repolens import __version__
from repolens.analyzers.base import Analyzer
from repolens.config import ScanConfig
from repolens.discovery import DiscoveredFile, RepositoryContext
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
    tool="repolens-documentation",
    tool_version=__version__,
)

_README_NAMES = frozenset({"readme", "readme.md", "readme.rst", "readme.txt", "readme.adoc"})
_LICENSE_NAMES = frozenset(
    {
        "license",
        "license.md",
        "license.txt",
        "license.rst",
        "licence",
        "licence.md",
        "licence.txt",
        "copying",
        "copying.md",
        "copying.txt",
    }
)

_MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]\n]{0,200}\]\(\s*([^)\s]{1,300})\s*\)")
_EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:", "#", "data:")
_MAX_LINK_FINDINGS = 10
_MAX_LINKS_EVALUATED = 500

# Marker phrases used to confirm that a LICENSE file plausibly matches a declared SPDX id.
_SPDX_LICENSE_MARKERS: dict[str, tuple[str, ...]] = {
    "MIT": ("mit license", "permission is hereby granted, free of charge"),
    "ISC": ("isc license", "permission to use, copy, modify"),
    "Apache-2.0": ("apache license", "version 2.0"),
    "BSD-2-Clause": ("redistribution and use in source and binary forms", "2-clause"),
    "BSD-3-Clause": ("neither the name", "redistribution and use in source and binary forms"),
    "GPL-2.0": ("gnu general public license", "version 2"),
    "GPL-3.0": ("gnu general public license", "version 3"),
    "AGPL-3.0": ("gnu affero general public license",),
    "LGPL-3.0": ("gnu lesser general public license",),
    "MPL-2.0": ("mozilla public license", "version 2.0"),
    "Unlicense": ("this is free and unencumbered software",),
    "CC0-1.0": ("cc0 1.0", "creative commons zero"),
}


def _as_mapping(value: object) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _normalize_spdx(value: str) -> list[str]:
    """Split compound SPDX expressions into individual license identifiers."""
    tokens = re.split(r"\s+(?:OR|AND|WITH)\s+", value.strip(), flags=re.IGNORECASE)
    return [token.strip().strip("()") for token in tokens if token.strip()]


class DocumentationAnalyzer(Analyzer):
    """Check manifest/documentation cross-references and license declarations."""

    @property
    def name(self) -> str:
        return "documentation-consistency"

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        self._reset_reporting()
        findings: list[Finding] = []
        findings.extend(self._check_manifest_references(context))
        findings.extend(self._check_readme_links(context))
        findings.extend(self._check_license_declaration(context))
        findings.extend(self._check_conflicting_license_declarations(context))

        deduped: dict[str, Finding] = {}
        for finding in findings:
            deduped.setdefault(finding.fingerprint, finding)
        return self._limit_findings(list(deduped.values()), config.max_findings_per_analyzer)

    # -- manifest references --------------------------------------------------------

    def _check_manifest_references(self, context: RepositoryContext) -> list[Finding]:
        findings: list[Finding] = []

        pyproject = context.files_by_path.get("pyproject.toml")
        if pyproject is not None and not pyproject.is_oversized and not pyproject.is_sensitive:
            try:
                data = tomllib.loads(context.read_text("pyproject.toml"))
            except tomllib.TOMLDecodeError:
                data = {}
            project = _as_mapping(data.get("project"))
            readme = project.get("readme")
            if isinstance(readme, str) and readme.strip():
                findings.extend(
                    self._missing_reference(
                        context, "pyproject.toml", readme.strip(), kind="readme"
                    )
                )
            elif isinstance(readme, dict):
                readme_file = _as_mapping(readme).get("file")
                if isinstance(readme_file, str) and readme_file.strip():
                    findings.extend(
                        self._missing_reference(
                            context, "pyproject.toml", readme_file.strip(), kind="readme"
                        )
                    )

        findings.extend(self._check_manifest_license_file(context))
        return findings

    def _missing_reference(
        self, context: RepositoryContext, manifest: str, reference: str, *, kind: str
    ) -> list[Finding]:
        cleaned = reference.replace("\\", "/").lstrip("./")
        if not cleaned or ".." in PurePosixPath(cleaned).parts:
            return []
        if self._path_exists(context, cleaned):
            return []
        return [
            Finding(
                rule_id="RL-DOC-001",
                category=Category.DOCUMENTATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title=f"Manifest references a missing {kind} file",
                location=FindingLocation(path=manifest),
                evidence=f"`{manifest}` declares `{reference}` which does not exist.",
                explanation=(
                    "Packaging metadata that points at a missing file breaks builds and "
                    "publish steps for readers of the package."
                ),
                recommendation=f"Create `{cleaned}` or update the reference in `{manifest}`.",
                verification=f"Confirm `{cleaned}` exists at the declared path.",
                source=_SOURCE,
            )
        ]

    def _check_manifest_license_file(self, context: RepositoryContext) -> list[Finding]:
        pyproject = context.files_by_path.get("pyproject.toml")
        if pyproject is None or pyproject.is_oversized or pyproject.is_sensitive:
            return []
        try:
            data = tomllib.loads(context.read_text("pyproject.toml"))
        except tomllib.TOMLDecodeError:
            return []

        license_entry = _as_mapping(data.get("project")).get("license")
        if not isinstance(license_entry, dict):
            return []
        license_file = _as_mapping(license_entry).get("file")
        if not isinstance(license_file, str) or not license_file.strip():
            return []

        cleaned = license_file.strip().replace("\\", "/").lstrip("./")
        if not cleaned or ".." in PurePosixPath(cleaned).parts:
            return []
        if self._path_exists(context, cleaned):
            return []

        return [
            Finding(
                rule_id="RL-DOC-002",
                category=Category.DOCUMENTATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Manifest references a missing license file",
                location=FindingLocation(path="pyproject.toml"),
                evidence=f"`pyproject.toml` declares license file `{license_file}`.",
                explanation=(
                    "A declared license file that does not exist produces broken package "
                    "metadata and can fail builds that validate the distribution."
                ),
                recommendation=f"Create `{cleaned}` or correct the license declaration.",
                verification=f"Confirm `{cleaned}` exists and contains the intended license.",
                source=_SOURCE,
            )
        ]

    # -- README links ---------------------------------------------------------------

    def _check_readme_links(self, context: RepositoryContext) -> list[Finding]:
        readme = self._root_readme(context)
        if readme is None or readme.is_oversized or readme.is_sensitive:
            return []

        text = context.read_text(readme.path)
        findings: list[Finding] = []
        evaluated = 0
        for number, line in enumerate(text.splitlines(), start=1):
            for match in _MARKDOWN_LINK_RE.finditer(line):
                target = match.group(1).strip()
                if not target or target.lower().startswith(_EXTERNAL_PREFIXES):
                    continue
                if any(char in target for char in ("{", "}", "<", ">", "%", "\\", "\x00")):
                    continue
                cleaned = target.split("#", 1)[0].split("?", 1)[0].strip()
                if not cleaned or cleaned.startswith("/"):
                    continue
                base = PurePosixPath(readme.path).parent
                candidate = (
                    cleaned if base == PurePosixPath(".") else f"{base.as_posix()}/{cleaned}"
                )
                if ".." in PurePosixPath(candidate).parts:
                    continue
                # Look ahead to the next eligible link before declaring a limit hit.
                # The README itself is already bounded by safe discovery.
                if len(findings) >= _MAX_LINK_FINDINGS:
                    self._mark_reporting_failure(
                        f"README broken-link findings reached the {_MAX_LINK_FINDINGS}-finding "
                        "limit; remaining eligible links were not checked."
                    )
                    return findings
                if evaluated >= _MAX_LINKS_EVALUATED:
                    self._mark_reporting_failure(
                        f"README link checks reached the {_MAX_LINKS_EVALUATED}-link limit; "
                        "remaining eligible links were not checked."
                    )
                    return findings
                evaluated += 1
                if self._path_exists(context, candidate):
                    continue
                findings.append(
                    Finding(
                        rule_id="RL-DOC-003",
                        category=Category.DOCUMENTATION,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        title=f"README links to a missing path: {target[:120]}",
                        location=FindingLocation(path=readme.path, start_line=number),
                        evidence=f"Markdown link target `{target[:200]}` does not exist.",
                        explanation=(
                            "Broken relative documentation links confuse contributors and are "
                            "often a sign that files were moved or deleted without updating docs."
                        ),
                        recommendation=f"Fix the link target or restore `{candidate[:200]}`.",
                        verification="Open the rendered README and confirm the link resolves.",
                        source=_SOURCE,
                    )
                )
        return findings

    # -- license declarations -------------------------------------------------------

    def _check_license_declaration(self, context: RepositoryContext) -> list[Finding]:
        declared = self._declared_license_ids(context)
        if not declared:
            return []

        license_file = self._root_license(context)
        if license_file is None or license_file.is_oversized or license_file.is_sensitive:
            return []

        text = context.read_text(license_file.path).lower()
        known = [identifier for identifier in declared if identifier in _SPDX_LICENSE_MARKERS]
        if not known:
            return []

        def matches(identifier: str) -> bool:
            markers = _SPDX_LICENSE_MARKERS[identifier]
            return any(marker in text for marker in markers)

        if any(matches(identifier) for identifier in known):
            return []

        joined = ", ".join(known)
        return [
            Finding(
                rule_id="RL-DOC-004",
                category=Category.DOCUMENTATION,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title="Declared license does not match LICENSE file content",
                location=FindingLocation(path=license_file.path),
                evidence=(
                    f"Manifest declares {joined}, but {license_file.path} does not contain the "
                    "expected license text."
                ),
                explanation=(
                    "Conflicting license metadata creates legal ambiguity for anyone using or "
                    "redistributing the project."
                ),
                recommendation=(
                    "Make the manifest license identifier and the LICENSE file agree, or use "
                    "the canonical license text for the declared SPDX identifier."
                ),
                verification="Compare the declared SPDX identifier with the LICENSE file text.",
                source=_SOURCE,
            )
        ]

    def _check_conflicting_license_declarations(self, context: RepositoryContext) -> list[Finding]:
        declarations = self._license_declarations_by_manifest(context)
        if len(declarations) < 2:
            return []

        sets = {path: set(identifiers) for path, identifiers in declarations.items()}
        first_path, first_ids = next(iter(sorted(sets.items())))
        for path, identifiers in sorted(sets.items())[1:]:
            if not identifiers or not first_ids:
                return []
            if identifiers & first_ids:
                return []
            evidence = "; ".join(
                f"{manifest} declares {', '.join(sorted(ids))}"
                for manifest, ids in sorted(sets.items())
            )
            return [
                Finding(
                    rule_id="RL-DOC-005",
                    category=Category.DOCUMENTATION,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    title="Conflicting license declarations across manifests",
                    location=FindingLocation(path=path),
                    evidence=evidence,
                    explanation=(
                        "Different manifests in the same repository declare incompatible "
                        "licenses, so consumers cannot determine the project's actual terms."
                    ),
                    recommendation=(
                        f"Align the license declarations in {first_path} and {path}, and make "
                        "the LICENSE file match."
                    ),
                    verification=(
                        "Compare the license fields in every root manifest with the LICENSE file."
                    ),
                    source=_SOURCE,
                )
            ]
        return []

    @staticmethod
    def _declared_license_ids(context: RepositoryContext) -> list[str]:
        identifiers: list[str] = []

        pyproject = context.files_by_path.get("pyproject.toml")
        if pyproject is not None and not pyproject.is_oversized and not pyproject.is_sensitive:
            try:
                data = tomllib.loads(context.read_text("pyproject.toml"))
            except tomllib.TOMLDecodeError:
                data = {}
            project = _as_mapping(data.get("project"))
            raw = project.get("license")
            if isinstance(raw, str):
                identifiers.extend(_normalize_spdx(raw))
            else:
                tool = _as_mapping(data.get("tool"))
                poetry = _as_mapping(tool.get("poetry"))
                poetry_license = poetry.get("license")
                if isinstance(poetry_license, str):
                    identifiers.extend(_normalize_spdx(poetry_license))

        package_json = context.files_by_path.get("package.json")
        if (
            package_json is not None
            and not package_json.is_oversized
            and not package_json.is_sensitive
        ):
            package_data: object = None
            try:
                package_data = json.loads(context.read_text("package.json"))
            except (json.JSONDecodeError, RecursionError):
                package_data = None
            if isinstance(package_data, dict):
                raw = cast("dict[str, Any]", package_data).get("license")
                if isinstance(raw, str):
                    identifiers.extend(_normalize_spdx(raw))

        return identifiers

    @staticmethod
    def _license_declarations_by_manifest(
        context: RepositoryContext,
    ) -> dict[str, list[str]]:
        """Return single-license declarations keyed by manifest path."""
        declarations: dict[str, list[str]] = {}

        pyproject = context.files_by_path.get("pyproject.toml")
        if pyproject is not None and not pyproject.is_oversized and not pyproject.is_sensitive:
            try:
                data = tomllib.loads(context.read_text("pyproject.toml"))
            except tomllib.TOMLDecodeError:
                data = {}
            project = _as_mapping(data.get("project"))
            raw = project.get("license")
            if isinstance(raw, str):
                declarations["pyproject.toml"] = _normalize_spdx(raw)
            else:
                poetry = _as_mapping(_as_mapping(data.get("tool")).get("poetry"))
                poetry_license = poetry.get("license")
                if isinstance(poetry_license, str):
                    declarations["pyproject.toml"] = _normalize_spdx(poetry_license)

        package_json = context.files_by_path.get("package.json")
        if (
            package_json is not None
            and not package_json.is_oversized
            and not package_json.is_sensitive
        ):
            try:
                package_data: object = json.loads(context.read_text("package.json"))
            except (json.JSONDecodeError, RecursionError):
                package_data = None
            if isinstance(package_data, dict):
                raw = cast("dict[str, Any]", package_data).get("license")
                if isinstance(raw, str):
                    declarations["package.json"] = _normalize_spdx(raw)

        return declarations

    # -- helpers --------------------------------------------------------------------

    @staticmethod
    def _root_readme(context: RepositoryContext) -> DiscoveredFile | None:
        for item in context.files:
            if "/" not in item.path and item.path.lower() in _README_NAMES:
                return item
        return None

    @staticmethod
    def _root_license(context: RepositoryContext) -> DiscoveredFile | None:
        for item in context.files:
            if "/" not in item.path and item.path.lower() in _LICENSE_NAMES:
                return item
        return None

    @staticmethod
    def _path_exists(context: RepositoryContext, candidate: str) -> bool:
        normalized = candidate.strip("/").replace("\\", "/")
        if not normalized:
            return True
        if normalized in context.files_by_path:
            return True
        prefix = f"{normalized}/"
        return any(item.path.startswith(prefix) for item in context.files)


__all__ = ["DocumentationAnalyzer"]
