"""Unit tests for the hardened OSV.dev client (all network access is mocked)."""

from __future__ import annotations

import json
import urllib.error
from collections.abc import Mapping
from typing import Any

import pytest

from repolens.osv import (
    OSV_API_BASE,
    OSV_QUERY_BATCH_PATH,
    OsvClient,
    OsvNetworkError,
    OsvPackage,
    OsvResponseError,
    OsvTimeoutError,
    UrllibOsvTransport,
)


class FakeTransport:
    """In-memory OSV transport that records every request payload."""

    def __init__(
        self,
        *,
        batch: Any,
        details: Mapping[str, Any] | None = None,
        post_error: Exception | None = None,
        get_error: Exception | None = None,
    ) -> None:
        self.batch = batch
        self.details = dict(details or {})
        self.post_error = post_error
        self.get_error = get_error
        self.posted: list[tuple[str, Mapping[str, object]]] = []
        self.fetched: list[str] = []

    def post_json(self, path: str, payload: Mapping[str, object]) -> bytes:
        self.posted.append((path, payload))
        if self.post_error is not None:
            raise self.post_error
        return json.dumps(self.batch).encode("utf-8")

    def get_json(self, path: str) -> bytes:
        self.fetched.append(path)
        if self.get_error is not None:
            raise self.get_error
        vuln_id = path.rsplit("/", 1)[-1]
        return json.dumps(self.details.get(vuln_id, {"id": vuln_id})).encode("utf-8")


def _package(name: str = "requests", version: str = "2.31.0") -> OsvPackage:
    return OsvPackage(name=name, version=version, ecosystem="PyPI")


def test_query_returns_enriched_vulnerabilities() -> None:
    transport = FakeTransport(
        batch={
            "results": [
                {"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz", "modified": "2026-01-01T00:00:00Z"}]}
            ]
        },
        details={
            "GHSA-xxxx-yyyy-zzzz": {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "summary": "Requests vulnerable to credential leak",
                "database_specific": {"severity": "HIGH"},
                "aliases": ["CVE-2024-12345"],
                "affected": [
                    {
                        "package": {"name": "requests", "ecosystem": "PyPI"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}],
                    }
                ],
            }
        },
    )
    client = OsvClient(transport=transport)
    vulnerabilities = client.query([_package()])

    assert len(vulnerabilities) == 1
    vuln = vulnerabilities[0]
    assert vuln.vuln_id == "GHSA-xxxx-yyyy-zzzz"
    assert vuln.severity.value == "high"
    assert vuln.confidence.value == "high"
    assert vuln.fixed_versions == ("2.32.0",)
    assert vuln.aliases == ("CVE-2024-12345",)
    assert vuln.package.name == "requests"
    assert vuln.display_url == "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz"
    assert vuln.advisory_url == f"{OSV_API_BASE}/v1/vulns/GHSA-xxxx-yyyy-zzzz"
    assert transport.fetched == ["/v1/vulns/GHSA-xxxx-yyyy-zzzz"]


def test_query_payload_contains_only_package_coordinates() -> None:
    transport = FakeTransport(batch={"results": [{"vulns": []}]})
    client = OsvClient(transport=transport)
    client.query([_package("django", "4.2.0")])

    path, payload = transport.posted[0]
    assert path == OSV_QUERY_BATCH_PATH
    assert payload == {
        "queries": [{"package": {"name": "django", "ecosystem": "PyPI"}, "version": "4.2.0"}]
    }
    serialized = json.dumps(payload)
    assert "path" not in serialized.lower()
    assert "repo" not in serialized.lower()
    assert "token" not in serialized.lower()


def test_query_batches_large_inventories() -> None:
    packages = [_package(f"pkg{i}", "1.0.0") for i in range(150)]
    transport = FakeTransport(batch={"results": [{"vulns": []} for _ in range(100)]})
    client = OsvClient(transport=transport)
    client.query(packages)

    batch_sizes = [len(payload["queries"]) for _, payload in transport.posted]  # type: ignore[arg-type]
    assert batch_sizes == [100, 50]


def test_query_deduplicates_identical_coordinates() -> None:
    transport = FakeTransport(
        batch={"results": [{"vulns": [{"id": "OSV-2026-1"}]}, {"vulns": [{"id": "OSV-2026-1"}]}]},
        details={"OSV-2026-1": {"id": "OSV-2026-1", "summary": "dup", "database_specific": {}}},
    )
    client = OsvClient(transport=transport)
    vulnerabilities = client.query([_package(), _package()])
    assert len(vulnerabilities) == 1


def test_cvss_numeric_score_is_mapped_to_severity() -> None:
    transport = FakeTransport(
        batch={"results": [{"vulns": [{"id": "OSV-2026-2"}]}]},
        details={
            "OSV-2026-2": {
                "id": "OSV-2026-2",
                "summary": "critical issue",
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            }
        },
    )
    vulnerabilities = OsvClient(transport=transport).query([_package()])
    assert vulnerabilities[0].severity.value == "critical"
    assert vulnerabilities[0].confidence.value == "high"


def test_missing_severity_defaults_to_medium_low_confidence() -> None:
    transport = FakeTransport(
        batch={"results": [{"vulns": [{"id": "OSV-2026-3"}]}]},
        details={"OSV-2026-3": {"id": "OSV-2026-3", "summary": "unspecified"}},
    )
    vulnerabilities = OsvClient(transport=transport).query([_package()])
    assert vulnerabilities[0].severity.value == "medium"
    assert vulnerabilities[0].confidence.value == "low"


def test_missing_summary_uses_placeholder() -> None:
    transport = FakeTransport(
        batch={"results": [{"vulns": [{"id": "OSV-2026-4"}]}]},
        details={"OSV-2026-4": {"id": "OSV-2026-4", "database_specific": {"severity": "LOW"}}},
    )
    vulnerabilities = OsvClient(transport=transport).query([_package()])
    assert "No advisory summary" in vulnerabilities[0].summary


def test_malformed_json_response_raises() -> None:
    class BrokenTransport(FakeTransport):
        def post_json(self, path: str, payload: Mapping[str, object]) -> bytes:
            return b"<html>not json</html>"

    with pytest.raises(OsvResponseError, match="unreadable payload"):
        OsvClient(transport=BrokenTransport(batch={})).query([_package()])


def test_unexpected_response_shape_raises() -> None:
    transport = FakeTransport(batch={"vulns": []})
    with pytest.raises(OsvResponseError, match="results list"):
        OsvClient(transport=transport).query([_package()])


def test_max_advisories_limits_detail_fetches() -> None:
    results = [{"vulns": [{"id": f"OSV-2026-{index}"} for index in range(10)]}]
    transport = FakeTransport(batch={"results": results})
    client = OsvClient(transport=transport, max_advisories=3)
    vulnerabilities = client.query([_package()])
    assert len(transport.fetched) == 3
    assert len(vulnerabilities) == 3


def test_network_and_timeout_errors_propagate() -> None:
    with pytest.raises(OsvNetworkError):
        OsvClient(transport=FakeTransport(batch={}, post_error=OsvNetworkError("offline"))).query(
            [_package()]
        )
    with pytest.raises(OsvTimeoutError):
        OsvClient(transport=FakeTransport(batch={}, post_error=OsvTimeoutError("timeout"))).query(
            [_package()]
        )
    with pytest.raises(OsvResponseError):
        OsvClient(
            transport=FakeTransport(
                batch={"results": [{"vulns": [{"id": "OSV-1"}]}]},
                get_error=OsvResponseError("bad detail"),
            )
        ).query([_package()])


def test_empty_inventory_short_circuits() -> None:
    transport = FakeTransport(batch={})
    assert OsvClient(transport=transport).query([]) == []
    assert transport.posted == []


class FakeResponse:
    def __init__(self, body: bytes, *, status: int = 200, headers: dict[str, str] | None = None):
        self._body = body
        self.status = status
        self.headers = headers or {}

    def read(self, size: int = -1) -> bytes:
        return self._body[:size] if size >= 0 else self._body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FakeOpener:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: float) -> FakeResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response


def _transport(opener: FakeOpener) -> UrllibOsvTransport:
    transport = UrllibOsvTransport(timeout_seconds=1.0, max_response_bytes=1024)
    transport._opener = opener  # type: ignore[assignment]
    return transport


def test_urllib_transport_sends_only_validated_https_requests() -> None:
    opener = FakeOpener(FakeResponse(b'{"ok": true}'))
    transport = _transport(opener)
    assert transport.get_json("/v1/vulns/OSV-1") == b'{"ok": true}'
    request = opener.requests[0]
    assert request.full_url == f"{OSV_API_BASE}/v1/vulns/OSV-1"
    assert request.get_method() == "GET"


@pytest.mark.parametrize(
    "path",
    ["/v2/evil", "v1/querybatch", "/v1/../secret", "https://evil.example.com/v1/x", "/v1/x\x00"],
)
def test_urllib_transport_rejects_unsafe_paths(path: str) -> None:
    transport = _transport(FakeOpener(FakeResponse(b"{}")))
    with pytest.raises(OsvResponseError):
        transport.get_json(path)


def test_urllib_transport_rejects_oversized_responses() -> None:
    opener = FakeOpener(FakeResponse(b"x" * 2048))
    with pytest.raises(OsvResponseError, match="response-size limit"):
        _transport(opener).get_json("/v1/vulns/OSV-1")

    opener = FakeOpener(FakeResponse(b"{}", headers={"Content-Length": "99999"}))
    with pytest.raises(OsvResponseError, match="response-size limit"):
        _transport(opener).get_json("/v1/vulns/OSV-1")


def test_urllib_transport_maps_errors() -> None:
    timeout_opener = FakeOpener(error=urllib.error.URLError(TimeoutError("timed out")))
    with pytest.raises(OsvTimeoutError):
        _transport(timeout_opener).get_json("/v1/vulns/OSV-1")

    dns_opener = FakeOpener(error=urllib.error.URLError("name resolution failed"))
    with pytest.raises(OsvNetworkError):
        _transport(dns_opener).get_json("/v1/vulns/OSV-1")

    rate_limited = FakeOpener(FakeResponse(b"{}", status=429))
    with pytest.raises(OsvNetworkError, match="429"):
        _transport(rate_limited).get_json("/v1/vulns/OSV-1")

    server_error = FakeOpener(FakeResponse(b"{}", status=500))
    with pytest.raises(OsvNetworkError, match="500"):
        _transport(server_error).get_json("/v1/vulns/OSV-1")


def test_redirect_handler_refuses_to_follow_redirects() -> None:
    from repolens.osv import _NoRedirectHandler

    handler = _NoRedirectHandler()
    with pytest.raises(OsvNetworkError, match="redirect"):
        handler.redirect_request(
            None,  # type: ignore[arg-type]
            None,
            302,
            "Found",
            None,
            "https://evil.example.com/",
        )


def test_urllib_transport_post_includes_json_body_and_headers() -> None:
    opener = FakeOpener(FakeResponse(b'{"results": []}'))
    transport = _transport(opener)

    payload = {"queries": [{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}]}
    assert transport.post_json(OSV_QUERY_BATCH_PATH, payload) == b'{"results": []}'

    request = opener.requests[0]
    assert request.full_url == f"{OSV_API_BASE}{OSV_QUERY_BATCH_PATH}"
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert json.loads(request.data.decode("utf-8")) == payload


def test_urllib_transport_maps_plain_timeout_error() -> None:
    transport = UrllibOsvTransport(timeout_seconds=1.0, max_response_bytes=1024)

    class RaisingOpener:
        def open(self, request: Any, timeout: float) -> Any:
            raise TimeoutError("timed out")

    transport._opener = RaisingOpener()  # type: ignore[assignment]
    with pytest.raises(OsvTimeoutError):
        transport.get_json("/v1/vulns/OSV-1")

    class OSErrorOpener:
        def open(self, request: Any, timeout: float) -> Any:
            raise OSError("socket failure")

    transport._opener = OSErrorOpener()  # type: ignore[assignment]
    with pytest.raises(OsvNetworkError):
        transport.get_json("/v1/vulns/OSV-1")


def test_total_time_budget_stops_detail_fetches() -> None:
    transport = FakeTransport(
        batch={"results": [{"vulns": [{"id": "OSV-2026-9"}]}]},
    )
    client = OsvClient(transport=transport, total_timeout_seconds=0.0)
    vulnerabilities = client.query([_package()])

    assert transport.fetched == []
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].confidence.value == "low"
    assert "No advisory summary" in vulnerabilities[0].summary
