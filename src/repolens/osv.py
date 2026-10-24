"""Minimal, hardened OSV.dev API client used for opt-in vulnerability lookups.

Design constraints:

* Only the OSV.dev batch-query and vulnerability-detail endpoints are contacted.
* Requests carry only package name, version, and ecosystem (never repository paths,
  source code, or credentials).
* HTTPS is enforced, redirects are rejected, and every request has a timeout plus a
  hard response-size ceiling.
* All responses are treated as untrusted input and parsed defensively.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

from repolens import __version__
from repolens.exceptions import RepoLensError
from repolens.models import Confidence, Severity

OSV_API_BASE = "https://api.osv.dev"
OSV_QUERY_BATCH_PATH = "/v1/querybatch"
OSV_VULN_PATH_PREFIX = "/v1/vulns/"

MAX_BATCH_SIZE = 100
_MAX_VULN_ID_LENGTH = 128

_USER_AGENT = f"repolens/{__version__} (static dependency audit)"


class OsvError(RepoLensError):
    """Base class for OSV interactions that could not be completed."""


class OsvNetworkError(OsvError):
    """Raised when OSV.dev is unreachable or returns an unusable HTTP response."""


class OsvTimeoutError(OsvError):
    """Raised when an OSV.dev request exceeds its time budget."""


class OsvResponseError(OsvError):
    """Raised when OSV.dev returns a payload RepoLens cannot interpret safely."""


@dataclass(frozen=True, slots=True)
class OsvPackage:
    """A single package coordinate submitted to OSV.dev."""

    name: str
    version: str
    ecosystem: str


@dataclass(frozen=True, slots=True)
class OsvVulnerability:
    """A vulnerability affecting a specific package coordinate."""

    vuln_id: str
    package: OsvPackage
    summary: str
    severity: Severity
    confidence: Confidence
    aliases: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()

    @property
    def advisory_url(self) -> str:
        return f"{OSV_API_BASE}{OSV_VULN_PATH_PREFIX}{self.vuln_id}"

    @property
    def display_url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.vuln_id}"


class OsvTransport(Protocol):
    """HTTP transport abstraction so tests never require live network access."""

    def post_json(self, path: str, payload: Mapping[str, object]) -> bytes:
        """POST ``payload`` as JSON to ``path`` and return the raw response body."""

    def get_json(self, path: str) -> bytes:
        """GET ``path`` and return the raw response body."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every redirect so responses can only come from the OSV.dev origin."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise OsvNetworkError("OSV.dev returned an unexpected redirect; request aborted.")


class UrllibOsvTransport:
    """Default HTTPS transport with timeouts, size caps, and no redirects."""

    def __init__(self, *, timeout_seconds: float, max_response_bytes: int) -> None:
        self._timeout = timeout_seconds
        self._max_bytes = max_response_bytes
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def post_json(self, path: str, payload: Mapping[str, object]) -> bytes:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - constant, validated HTTPS origin
            self._build_url(path),
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": _USER_AGENT,
            },
        )
        return self._execute(request)

    def get_json(self, path: str) -> bytes:
        request = urllib.request.Request(  # noqa: S310 - constant, validated HTTPS origin
            self._build_url(path),
            method="GET",
            headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
        )
        return self._execute(request)

    @staticmethod
    def _build_url(path: str) -> str:
        if not path.startswith("/v1/") or ".." in path or "://" in path or "\x00" in path:
            raise OsvResponseError("Refusing to build an unsafe OSV request URL.")
        return f"{OSV_API_BASE}{path}"

    def _execute(self, request: urllib.request.Request) -> bytes:
        # `urlopen` receives a constant, scheme-validated HTTPS URL and a rejecting
        # redirect handler, so user-supplied URLs can never reach the network.
        try:
            # URL scheme and host are validated by `_build_url`; redirects are rejected.
            with self._opener.open(  # nosec B310 - validated HTTPS origin, no redirects
                request, timeout=self._timeout
            ) as response:
                status = getattr(response, "status", 200)
                if status == 429:
                    raise OsvNetworkError("OSV.dev rate limited the request (HTTP 429).")
                if status >= 400:
                    raise OsvNetworkError(f"OSV.dev responded with HTTP {status}.")
                length_header = response.headers.get("Content-Length") if response.headers else None
                if length_header is not None:
                    try:
                        declared = int(length_header)
                    except ValueError:
                        declared = 0
                    if declared > self._max_bytes:
                        raise OsvResponseError(
                            "OSV.dev response exceeded the configured response-size limit."
                        )
                payload = cast("bytes", response.read(self._max_bytes + 1))
        except urllib.error.HTTPError as exc:
            raise OsvNetworkError(f"OSV.dev returned HTTP {exc.code}.") from exc
        except TimeoutError as exc:
            raise OsvTimeoutError("OSV.dev request timed out.") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise OsvTimeoutError("OSV.dev request timed out.") from exc
            raise OsvNetworkError("OSV.dev is unreachable from this environment.") from exc
        except OSError as exc:
            raise OsvNetworkError(f"OSV.dev request failed: {type(exc).__name__}.") from exc

        if len(payload) > self._max_bytes:
            raise OsvResponseError("OSV.dev response exceeded the configured response-size limit.")
        return payload


_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_CVSS_THRESHOLDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


def _as_mapping(value: object) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _safe_vuln_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned or len(cleaned) > _MAX_VULN_ID_LENGTH:
        return None
    if not all(char.isalnum() or char in "-_" for char in cleaned):
        return None
    return cleaned


def _severity_from_advisory(data: dict[str, Any]) -> tuple[Severity, Confidence]:
    database_specific = _as_mapping(data.get("database_specific"))
    raw = database_specific.get("severity")
    if isinstance(raw, str):
        mapped = _SEVERITY_MAP.get(raw.strip().upper())
        if mapped is not None:
            return mapped, Confidence.HIGH

    severity_entries = data.get("severity")
    if isinstance(severity_entries, list):
        for entry in severity_entries:
            score = _as_mapping(entry).get("score")
            if isinstance(score, str):
                try:
                    numeric = float(score)
                except ValueError:
                    continue
                for threshold, severity in _CVSS_THRESHOLDS:
                    if numeric >= threshold:
                        return severity, Confidence.HIGH
    return Severity.MEDIUM, Confidence.LOW


def _fixed_versions(data: dict[str, Any], package_name: str) -> tuple[str, ...]:
    fixed: set[str] = set()
    affected = data.get("affected")
    if not isinstance(affected, list):
        return ()
    for raw in affected:
        entry = _as_mapping(raw)
        package = _as_mapping(entry.get("package"))
        if package.get("name") != package_name:
            continue
        ranges = entry.get("ranges")
        if not isinstance(ranges, list):
            continue
        for range_entry in ranges:
            events = _as_mapping(range_entry).get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                version = _as_mapping(event).get("fixed")
                if isinstance(version, str) and 0 < len(version) <= 64:
                    fixed.add(version)
    return tuple(sorted(fixed))


class OsvClient:
    """Query OSV.dev for vulnerabilities affecting an explicit package inventory."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 2_097_152,
        max_advisories: int = 50,
        total_timeout_seconds: float = 60.0,
        transport: OsvTransport | None = None,
    ) -> None:
        self._transport: OsvTransport = transport or UrllibOsvTransport(
            timeout_seconds=timeout_seconds, max_response_bytes=max_response_bytes
        )
        self._max_advisories = max_advisories
        self._total_timeout_seconds = total_timeout_seconds

    def query(self, packages: Sequence[OsvPackage]) -> list[OsvVulnerability]:
        """Return vulnerabilities affecting ``packages``, deduplicated by advisory ID."""
        if not packages:
            return []

        matches: list[OsvVulnerability] = []
        details: dict[str, dict[str, Any]] = {}

        for start in range(0, len(packages), MAX_BATCH_SIZE):
            batch = list(packages[start : start + MAX_BATCH_SIZE])
            payload = {
                "queries": [
                    {
                        "package": {"name": pkg.name, "ecosystem": pkg.ecosystem},
                        "version": pkg.version,
                    }
                    for pkg in batch
                ]
            }
            raw = self._transport.post_json(OSV_QUERY_BATCH_PATH, payload)
            response = self._decode(raw, "querybatch")
            results = response.get("results")
            if not isinstance(results, list):
                raise OsvResponseError("OSV.dev query response did not contain a results list.")

            for package, result in zip(batch, results, strict=False):
                vulns = _as_mapping(result).get("vulns")
                if not isinstance(vulns, list):
                    continue
                for raw_vuln in vulns:
                    vuln_id = _safe_vuln_id(_as_mapping(raw_vuln).get("id"))
                    if vuln_id is None:
                        continue
                    matches.append(
                        OsvVulnerability(
                            vuln_id=vuln_id,
                            package=package,
                            summary="",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                        )
                    )

        deduped: dict[tuple[str, str, str], OsvVulnerability] = {}
        for match in matches:
            key = (match.vuln_id, match.package.name.lower(), match.package.version)
            deduped.setdefault(key, match)

        unique_ids = sorted({match.vuln_id for match in deduped.values()})
        allowed_ids = unique_ids[: self._max_advisories]

        # Detail lookups are optional enrichment: they are bounded by an advisory cap and a
        # wall-clock budget so a slow service cannot stall the whole scan indefinitely.
        deadline = time.monotonic() + self._total_timeout_seconds
        for vuln_id in allowed_ids:
            if time.monotonic() >= deadline:
                break
            if vuln_id in details:
                continue
            details[vuln_id] = self._fetch_detail(vuln_id)

        enriched: list[OsvVulnerability] = []
        for match in deduped.values():
            if match.vuln_id not in allowed_ids:
                continue
            detail = details.get(match.vuln_id, {})
            severity, confidence = _severity_from_advisory(detail)
            summary_raw = detail.get("summary")
            summary = (
                " ".join(summary_raw.split())[:500]
                if isinstance(summary_raw, str) and summary_raw.strip()
                else "No advisory summary was provided by OSV.dev."
            )
            aliases_raw = detail.get("aliases")
            aliases: tuple[str, ...] = ()
            if isinstance(aliases_raw, list):
                aliases = tuple(
                    alias
                    for alias in (_safe_vuln_id(entry) for entry in aliases_raw)
                    if alias is not None
                )[:10]
            enriched.append(
                OsvVulnerability(
                    vuln_id=match.vuln_id,
                    package=match.package,
                    summary=summary,
                    severity=severity,
                    confidence=confidence,
                    aliases=aliases,
                    fixed_versions=_fixed_versions(detail, match.package.name),
                )
            )

        enriched.sort(
            key=lambda item: (-item.severity.rank, item.package.name.lower(), item.vuln_id)
        )
        return enriched

    def _fetch_detail(self, vuln_id: str) -> dict[str, Any]:
        raw = self._transport.get_json(f"{OSV_VULN_PATH_PREFIX}{vuln_id}")
        return self._decode(raw, vuln_id)

    @staticmethod
    def _decode(raw: bytes, context: str) -> dict[str, Any]:
        try:
            decoded = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OsvResponseError(
                f"OSV.dev returned an unreadable payload for {context}."
            ) from exc
        if not isinstance(decoded, dict):
            raise OsvResponseError(f"OSV.dev returned an unexpected payload for {context}.")
        return cast("dict[str, Any]", decoded)


__all__ = [
    "OSV_API_BASE",
    "OsvClient",
    "OsvError",
    "OsvNetworkError",
    "OsvPackage",
    "OsvResponseError",
    "OsvTimeoutError",
    "OsvTransport",
    "OsvVulnerability",
    "UrllibOsvTransport",
]
