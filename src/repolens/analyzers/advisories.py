"""Opt-in OSV.dev known-vulnerability analyzer for locked dependencies.

This analyzer is disabled unless ``ScanConfig(enable_network_checks=True)`` is set. It
sends only normalized package coordinates (name, version, ecosystem) to OSV.dev and never
claims a vulnerability without an advisory ID returned by the service.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol

from repolens.analyzers.base import (
    Analyzer,
    AnalyzerAvailability,
    AnalyzerExecutionError,
    AnalyzerTimeoutError,
    AnalyzerUnavailableError,
)
from repolens.config import ScanConfig
from repolens.dependencies import DependencyInventory, Ecosystem, build_dependency_inventory
from repolens.discovery import RepositoryContext
from repolens.models import (
    Category,
    Confidence,
    Finding,
    FindingLocation,
    FindingSource,
    SourceKind,
)
from repolens.osv import (
    OsvClient,
    OsvError,
    OsvNetworkError,
    OsvPackage,
    OsvTimeoutError,
    OsvVulnerability,
)


class VulnerabilityClient(Protocol):
    """Minimal client contract allowing tests to inject offline OSV doubles."""

    def query(self, packages: Sequence[OsvPackage]) -> list[OsvVulnerability]:
        """Return vulnerabilities affecting ``packages``."""


ClientFactory = Callable[[ScanConfig], VulnerabilityClient]


def _default_client_factory(config: ScanConfig) -> VulnerabilityClient:
    return OsvClient(
        timeout_seconds=config.network_timeout_seconds,
        max_response_bytes=config.max_network_response_bytes,
        max_advisories=config.max_osv_advisories,
        total_timeout_seconds=max(config.network_timeout_seconds * 6.0, 10.0),
    )


class OsvVulnerabilityAnalyzer(Analyzer):
    """Look up known vulnerabilities for locked Python and npm packages via OSV.dev."""

    def __init__(self, *, client_factory: ClientFactory | None = None) -> None:
        self._client_factory = client_factory or _default_client_factory
        self._message: str | None = None
        self._coverage_partial = False

    @property
    def name(self) -> str:
        return "osv-dependency-check"

    def _inventory(self, context: RepositoryContext) -> DependencyInventory:
        return build_dependency_inventory(context)

    def is_applicable(self, context: RepositoryContext) -> bool:
        return bool(self._inventory(context).unique_packages())

    def skip_reason(self, context: RepositoryContext, config: ScanConfig) -> str | None:
        if not config.enable_network_checks:
            return (
                "Network dependency checks are disabled. Pass "
                "`ScanConfig(enable_network_checks=True)` to query OSV.dev."
            )
        return None

    def check_availability(self) -> AnalyzerAvailability:
        return AnalyzerAvailability(available=True)

    def completion_message(self) -> str | None:
        return self._message

    def coverage_partial(self) -> bool:
        return self._coverage_partial

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        self._message = None
        self._coverage_partial = False
        inventory = self._inventory(context)
        available = inventory.unique_packages()
        coordinates = available[: config.max_osv_packages]
        # Packages beyond the query cap are never checked for known vulnerabilities, so a
        # clean result there would be misleading. Record it like any other coverage gap.
        self._coverage_partial = len(available) > len(coordinates)
        if not coordinates:
            self._message = "No locked package versions were available for OSV.dev lookup."
            return []

        packages = [
            OsvPackage(name=name, version=version, ecosystem=ecosystem.value)
            for name, version, ecosystem in coordinates
        ]

        client = self._client_factory(config)
        try:
            vulnerabilities = client.query(packages)
        except OsvTimeoutError as exc:
            raise AnalyzerTimeoutError(f"OSV.dev lookup timed out: {exc}") from exc
        except OsvNetworkError as exc:
            raise AnalyzerUnavailableError(f"OSV.dev lookup unavailable: {exc}") from exc
        except OsvError as exc:
            raise AnalyzerExecutionError(f"OSV.dev lookup failed: {exc}") from exc

        findings = self._build_findings(vulnerabilities, inventory, config)
        queried = f"Queried OSV.dev for {len(packages)}"
        if self._coverage_partial:
            queried += (
                f" of {len(available)} locked package version(s): the max_osv_packages limit "
                f"({config.max_osv_packages}) was reached, so the rest were not checked"
            )
        else:
            queried += " locked package version(s)"
        self._message = f"{queried}; {len(findings)} advisory finding(s) reported."
        return findings

    def _build_findings(
        self,
        vulnerabilities: Sequence[OsvVulnerability],
        inventory: DependencyInventory,
        config: ScanConfig,
    ) -> list[Finding]:
        location_index = self._location_index(inventory)
        seen: set[tuple[str, str, str]] = set()
        findings: list[Finding] = []

        for vuln in vulnerabilities:
            coordinate = (vuln.vuln_id, vuln.package.name.lower(), vuln.package.version)
            if coordinate in seen:
                continue
            seen.add(coordinate)
            if len(findings) >= config.max_findings_per_analyzer:
                break

            source_path = location_index.get((vuln.package.name.lower(), vuln.package.version))
            fixed = ", ".join(vuln.fixed_versions[:5]) if vuln.fixed_versions else ""
            recommendation = (
                f"Upgrade `{vuln.package.name}` to {fixed} or later, or apply the mitigation "
                "described in the advisory."
                if fixed
                else (
                    f"No fixed version is listed by OSV.dev for `{vuln.package.name}`. Review "
                    "the advisory for mitigations, or replace the dependency."
                )
            )
            explanation = (
                f"OSV.dev reports advisory {vuln.vuln_id} affecting "
                f"`{vuln.package.name}` {vuln.package.version} ({vuln.package.ecosystem})."
            )
            if vuln.aliases:
                explanation += f" Aliases: {', '.join(vuln.aliases[:5])}."
            if vuln.confidence is not Confidence.HIGH:
                explanation += " OSV.dev did not publish a severity rating; severity is estimated."

            findings.append(
                Finding(
                    rule_id=f"OSV-{vuln.vuln_id}"[:128],
                    category=Category.SECURITY,
                    severity=vuln.severity,
                    confidence=vuln.confidence,
                    title=f"{vuln.vuln_id}: {vuln.package.name} {vuln.package.version}",
                    location=(
                        FindingLocation(path=source_path) if source_path is not None else None
                    ),
                    evidence=vuln.summary[:500],
                    explanation=explanation[:4000],
                    recommendation=recommendation[:4000],
                    verification=(
                        f"Confirm advisory {vuln.vuln_id} at {vuln.display_url} and verify the "
                        f"installed `{vuln.package.name}` version is outside the affected range."
                    ),
                    source=FindingSource(
                        kind=SourceKind.DETERMINISTIC,
                        tool="osv.dev",
                        tool_version=None,
                        rule_url=vuln.display_url,
                    ),
                )
            )
        return findings

    @staticmethod
    def _location_index(inventory: DependencyInventory) -> dict[tuple[str, str], str]:
        index: dict[tuple[str, str], str] = {}
        for package in inventory.locked:
            if package.ecosystem not in (Ecosystem.PYPI, Ecosystem.NPM):
                continue
            key = (package.name.lower(), package.version)
            index.setdefault(key, package.source_path)
        return index


__all__ = ["OsvVulnerabilityAnalyzer"]
