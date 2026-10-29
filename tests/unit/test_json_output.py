"""Unit tests for the machine-readable JSON scan document.

The contract under test: one valid JSON document per scan whose body is exactly the existing
``ScanReport`` (no duplicated models), plus a ``result`` verdict that agrees with the exit
code, with stable member names, ordering, and value encodings.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from repolens.exceptions import (
    ScanDocumentError,
    UnsupportedSchemaValueError,
    UnsupportedSchemaVersionError,
)
from repolens.json_output import (
    build_json_document,
    build_scan_result,
    parse_json_document,
    render_json,
)
from repolens.models import (
    SCHEMA_MAJOR_VERSION,
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_MAJOR_VERSIONS,
    AnalyzerOutcome,
    AnalyzerStatus,
    Category,
    Finding,
    IncompleteReason,
    ScanReport,
    ScanResult,
    ScanStatus,
    Severity,
)

# The documented member order of the emitted document: ScanReport fields, then ``result``.
_EXPECTED_TOP_LEVEL_KEYS = [
    "schema_version",
    "repolens_version",
    "repository_name",
    "scanned_at",
    "duration_ms",
    "discovery",
    "analyzer_outcomes",
    "findings",
    "ai_advisories",
    "result",
]

_EXPECTED_RESULT_KEYS = [
    "exit_code",
    "min_severity",
    "status",
    "has_findings",
    "is_complete",
    "incomplete_reasons",
    "findings_total",
    "findings_at_or_above_threshold",
    "counts_by_severity",
    "counts_by_category",
]


def _loaded(document: str) -> dict[str, Any]:
    parsed = json.loads(document)
    assert isinstance(parsed, dict)
    return parsed


# --------------------------------------------------------------------------------------
# Shape, validity, and schema version
# --------------------------------------------------------------------------------------


def test_document_is_valid_json_with_documented_member_order(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    document = render_json(make_scan_report(), exit_code=0)

    parsed = _loaded(document)
    assert list(parsed) == _EXPECTED_TOP_LEVEL_KEYS
    result = parsed["result"]
    assert isinstance(result, dict)
    assert list(result) == _EXPECTED_RESULT_KEYS


def test_document_body_is_the_existing_report_model(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    """The report body must round-trip through ``ScanReport``: no duplicate schema."""
    report = make_scan_report(findings=[make_finding()])

    parsed = _loaded(render_json(report, exit_code=1))
    del parsed["result"]

    assert ScanReport.model_validate(parsed) == report


def test_schema_version_is_the_documented_contract_version(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report()
    parsed = _loaded(render_json(report, exit_code=0))

    assert parsed["schema_version"] == SCHEMA_VERSION == "1.1.0"
    assert report.schema_version == SCHEMA_VERSION


def test_result_block_validates_as_the_documented_model(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    parsed = _loaded(render_json(make_scan_report(), exit_code=0))

    result = ScanResult.model_validate(parsed["result"])
    assert result.status is ScanStatus.CLEAN
    assert set(result.counts_by_severity) == set(Severity)
    assert set(result.counts_by_category) == set(Category)


def _scan_result(**overrides: object) -> ScanResult:
    values: dict[str, object] = {
        "exit_code": 0,
        "min_severity": Severity.INFO,
        "status": ScanStatus.CLEAN,
        "has_findings": False,
        "is_complete": True,
        "findings_total": 0,
        "findings_at_or_above_threshold": 0,
        "counts_by_severity": dict.fromkeys(Severity, 0),
        "counts_by_category": dict.fromkeys(Category, 0),
    }
    values.update(overrides)
    return ScanResult.model_validate(values)


def test_result_model_accepts_a_complete_zero_count_map() -> None:
    result = _scan_result()

    assert result.counts_by_severity == dict.fromkeys(Severity, 0)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"counts_by_severity": {Severity.INFO: 0}}, "counts_by_severity"),
        ({"counts_by_category": {Category.SECURITY: 1}}, "counts_by_category"),
        ({"counts_by_severity": dict.fromkeys(Severity, -1)}, "must not be negative"),
        (
            {"counts_by_category": {**dict.fromkeys(Category, 0), Category.TESTING: -2}},
            "must not be negative",
        ),
    ],
)
def test_result_model_rejects_incomplete_or_negative_count_maps(
    overrides: dict[str, object], message: str
) -> None:
    """A consumer must be able to read every count key unconditionally."""
    with pytest.raises(ValidationError, match=message):
        _scan_result(**overrides)


def test_report_model_rejects_a_malformed_schema_version(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    data = make_scan_report().model_dump()
    data["schema_version"] = "1.1"
    with pytest.raises(ValidationError, match="schema_version"):
        ScanReport.model_validate(data)


# --------------------------------------------------------------------------------------
# Empty results, findings, and value encoding
# --------------------------------------------------------------------------------------


def test_empty_scan_reports_empty_collections_and_zero_counts(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    parsed = _loaded(render_json(make_scan_report(outcomes=[], total_files=0), exit_code=0))

    assert parsed["findings"] == []
    assert parsed["ai_advisories"] == []
    assert parsed["analyzer_outcomes"] == []
    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["status"] == "clean"
    assert result["has_findings"] is False
    assert result["is_complete"] is True
    assert result["incomplete_reasons"] == []
    assert result["findings_total"] == 0
    assert result["exit_code"] == 0
    # Every severity/category key is present even when nothing was found.
    assert result["counts_by_severity"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert list(result["counts_by_category"]) == [
        "code_quality",
        "security",
        "dependencies",
        "documentation",
        "testing",
        "structure",
    ]


def test_findings_are_fully_serialized_with_typed_values(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(path="src/app.py", start_line=12)
    parsed = _loaded(render_json(make_scan_report(findings=[finding]), exit_code=1))

    serialized = parsed["findings"][0]
    assert serialized["rule_id"] == "RL-STRUCT-001"
    assert serialized["severity"] == "medium"
    assert serialized["category"] == "structure"
    assert serialized["confidence"] == "high"
    assert serialized["location"] == {
        "path": "src/app.py",
        "start_line": 12,
        "end_line": None,
        "column": None,
    }
    assert serialized["source"] == {
        "kind": "deterministic",
        "tool": "repolens-structure",
        "tool_version": "0.1.0",
        "rule_url": None,
    }
    assert serialized["evidence"] is None
    assert serialized["fingerprint"]

    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["status"] == "findings"
    assert result["findings_total"] == 1
    assert result["counts_by_severity"]["medium"] == 1
    assert result["counts_by_category"]["structure"] == 1


def test_threshold_only_changes_the_verdict_not_the_findings(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(findings=[make_finding()])

    parsed = _loaded(render_json(report, exit_code=0, min_severity=Severity.HIGH))

    assert len(parsed["findings"]) == 1
    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["min_severity"] == "high"
    assert result["has_findings"] is False
    assert result["status"] == "clean"
    assert result["findings_total"] == 1
    assert result["findings_at_or_above_threshold"] == 0
    assert result["exit_code"] == 0


# --------------------------------------------------------------------------------------
# Incomplete scans, unavailable analyzers, and aborted checks
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (AnalyzerStatus.FAILED, IncompleteReason.ANALYZER_FAILED),
        (AnalyzerStatus.TIMED_OUT, IncompleteReason.ANALYZER_TIMED_OUT),
    ],
)
def test_failed_and_timed_out_analyzers_make_the_scan_incomplete(
    make_scan_report: Callable[..., ScanReport],
    status: AnalyzerStatus,
    reason: IncompleteReason,
) -> None:
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="bandit-python-security",
                status=status,
                message="analyzer did not finish",
            )
        ]
    )

    parsed = _loaded(render_json(report, exit_code=3))
    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["status"] == "incomplete"
    assert result["is_complete"] is False
    assert result["incomplete_reasons"] == [reason.value]
    assert result["exit_code"] == 3
    assert parsed["analyzer_outcomes"] == [
        {
            "analyzer_name": "bandit-python-security",
            "status": status.value,
            "findings_count": 0,
            "duration_ms": 0.0,
            "message": "analyzer did not finish",
            "coverage_truncated": False,
            "coverage_incomplete": False,
        }
    ]


def test_unavailable_analyzers_are_reported_but_do_not_make_the_scan_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.UNAVAILABLE,
                message="`ruff` executable was not found on PATH (optional tool not installed).",
            )
        ]
    )

    parsed = _loaded(render_json(report, exit_code=0))
    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["status"] == "clean"
    assert result["is_complete"] is True
    assert result["incomplete_reasons"] == []
    assert result["exit_code"] == 0
    outcomes = parsed["analyzer_outcomes"]
    assert isinstance(outcomes, list)
    assert outcomes[0]["status"] == "unavailable"
    assert outcomes[0]["coverage_incomplete"] is False
    assert "optional tool not installed" in outcomes[0]["message"]


def test_aborted_check_is_reported_as_an_incomplete_scan(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """A check that started and then failed is not a soft "not installed" outcome."""
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="osv-dependency-check",
                status=AnalyzerStatus.UNAVAILABLE,
                message="OSV.dev lookup failed mid-flight.",
                coverage_incomplete=True,
            )
        ]
    )

    parsed = _loaded(render_json(report, exit_code=3))
    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["is_complete"] is False
    assert result["incomplete_reasons"] == [IncompleteReason.CHECK_ABORTED.value]
    assert parsed["analyzer_outcomes"][0]["coverage_incomplete"] is True


def test_partial_coverage_analyzer_is_reported_as_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="ruff-python-lint",
                status=AnalyzerStatus.COMPLETED,
                findings_count=0,
                coverage_truncated=True,
            )
        ]
    )

    parsed = _loaded(render_json(report, exit_code=3))
    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["is_complete"] is False
    assert result["incomplete_reasons"] == [IncompleteReason.ANALYZER_COVERAGE_TRUNCATED.value]


def test_discovery_gaps_are_reported_with_distinct_reasons(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(
        unreadable_directory_count=2,
        unreadable_entry_count=1,
        skipped_by_depth_count=3,
        truncated_by_file_limit=True,
    )

    parsed = _loaded(render_json(report, exit_code=3))
    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["status"] == "incomplete"
    assert result["incomplete_reasons"] == [
        IncompleteReason.DISCOVERY_UNREADABLE.value,
        IncompleteReason.DISCOVERY_TRUNCATED.value,
        IncompleteReason.DISCOVERY_DEPTH_LIMITED.value,
    ]
    discovery = parsed["discovery"]
    assert discovery["unreadable_directory_count"] == 2
    assert discovery["unreadable_entry_count"] == 1
    assert discovery["skipped_by_depth_count"] == 3
    assert discovery["truncated_by_file_limit"] is True


def test_findings_and_incompleteness_are_both_reported(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(
        findings=[make_finding()],
        outcomes=[
            AnalyzerOutcome(analyzer_name="bandit-python-security", status=AnalyzerStatus.FAILED)
        ],
    )

    parsed = _loaded(render_json(report, exit_code=1))
    result = parsed["result"]
    assert isinstance(result, dict)
    assert result["status"] == "findings_and_incomplete"
    assert result["has_findings"] is True
    assert result["is_complete"] is False
    assert result["exit_code"] == 1


def test_incomplete_reasons_are_deduplicated_and_ordered(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(analyzer_name="a", status=AnalyzerStatus.FAILED),
            AnalyzerOutcome(analyzer_name="b", status=AnalyzerStatus.TIMED_OUT),
            AnalyzerOutcome(analyzer_name="c", status=AnalyzerStatus.TIMED_OUT),
        ]
    )

    result = build_scan_result(report, exit_code=3)
    assert [reason.value for reason in result.incomplete_reasons] == [
        "analyzer_failed",
        "analyzer_timed_out",
    ]


# --------------------------------------------------------------------------------------
# Determinism and portable encoding
# --------------------------------------------------------------------------------------


def test_document_is_byte_identical_for_the_same_report(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(findings=[make_finding(), make_finding(rule_id="RL-TEST-001")])

    first = render_json(report, exit_code=1)
    second = render_json(report, exit_code=1)

    assert first == second
    assert first == render_json(report, exit_code=1, min_severity=Severity.INFO)


def test_findings_keep_the_engine_provided_order(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    findings = [
        make_finding(rule_id="RL-CRIT-001", severity=Severity.CRITICAL),
        make_finding(rule_id="RL-LOW-001", severity=Severity.LOW),
        make_finding(rule_id="RL-MED-001", severity=Severity.MEDIUM),
    ]
    report = make_scan_report(findings=findings)

    parsed = _loaded(render_json(report, exit_code=1))

    assert [item["rule_id"] for item in parsed["findings"]] == [
        "RL-CRIT-001",
        "RL-LOW-001",
        "RL-MED-001",
    ]


def test_output_is_ascii_only_and_round_trips_non_ascii_names(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """Escaping keeps the bytes identical across consoles, including Windows code pages."""
    report = make_scan_report(repository_name="répo-ünïcode")

    document = render_json(report, exit_code=0)

    assert document.isascii()
    assert "r\\u00e9po-\\u00fcn\\u00efcode" in document
    assert _loaded(document)["repository_name"] == "répo-ünïcode"


def test_document_uses_two_space_indentation_and_no_trailing_newline(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    document = render_json(make_scan_report(), exit_code=0)

    assert document.startswith('{\n  "schema_version": ')
    assert not document.endswith("\n")


def test_build_json_document_matches_the_rendered_document(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report()

    assert json.loads(render_json(report, exit_code=0)) == build_json_document(report, exit_code=0)


def test_json_never_contains_ansi_escapes(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    assert "\x1b[" not in render_json(make_scan_report(), exit_code=0)


def test_document_round_trips_through_the_parser(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(findings=[make_finding()])

    parsed = parse_json_document(render_json(report, exit_code=1))

    assert parsed.report == report
    assert parsed.result.exit_code == 1
    assert parsed.result.status is ScanStatus.FINDINGS


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("[]", "must be a JSON object"),
        ('{"schema_version": "1.1.0"}', "missing the 'result' member"),
    ],
)
def test_parser_rejects_documents_that_do_not_match_the_contract(
    document: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_json_document(document)


def test_parser_rejects_a_malformed_result_block(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    body = make_scan_report().model_dump(mode="json")

    with pytest.raises(ValidationError):
        parse_json_document(json.dumps({**body, "result": {"exit_code": 0}}))


# --------------------------------------------------------------------------------------
# D1: schema-version validation
# --------------------------------------------------------------------------------------


def _document_with_version(report: ScanReport, version: str, exit_code: int = 0) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(render_json(report, exit_code=exit_code))
    document["schema_version"] = version
    return document


def test_supported_major_policy_matches_the_shipped_version() -> None:
    """The policy constant must never drift from ``SCHEMA_VERSION``."""
    assert int(SCHEMA_VERSION.split(".")[0]) == SCHEMA_MAJOR_VERSION
    assert frozenset({SCHEMA_MAJOR_VERSION}) == SUPPORTED_SCHEMA_MAJOR_VERSIONS


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0", "1.2.0", "1.99.7"])
def test_parser_accepts_any_minor_and_patch_within_the_supported_major(
    make_scan_report: Callable[..., ScanReport], version: str
) -> None:
    """Policy: same major → accepted, older or newer minor/patch alike."""
    document = _document_with_version(make_scan_report(), version)

    parsed = parse_json_document(json.dumps(document))

    assert parsed.report.schema_version == version
    assert parsed.result.status is ScanStatus.CLEAN


@pytest.mark.parametrize("version", ["2.0.0", "3.4.5", "0.9.0", "0.1.0"])
def test_parser_rejects_unsupported_major_versions(
    make_scan_report: Callable[..., ScanReport], version: str
) -> None:
    """A future or pre-1.0 major version must never be decoded under 1.x assumptions."""
    document = _document_with_version(make_scan_report(), version)

    with pytest.raises(UnsupportedSchemaVersionError, match="unsupported scan schema version"):
        parse_json_document(json.dumps(document))


def test_unsupported_version_error_names_both_versions_and_is_a_value_error(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    document = _document_with_version(make_scan_report(), "2.0.0")

    with pytest.raises(UnsupportedSchemaVersionError) as captured:
        parse_json_document(json.dumps(document))

    message = str(captured.value)
    assert "2.0.0" in message
    assert SCHEMA_VERSION in message
    assert "upgrade RepoLens" in message
    # Documented as a ValueError subclass so existing ``except ValueError`` blocks work.
    assert isinstance(captured.value, ValueError)
    assert isinstance(captured.value, ScanDocumentError)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(schema_version="1.1"), "malformed scan schema version"),
        (lambda d: d.update(schema_version="1"), "malformed scan schema version"),
        (lambda d: d.update(schema_version="v1.1.0"), "malformed scan schema version"),
        (lambda d: d.update(schema_version=""), "malformed scan schema version"),
        (lambda d: d.pop("schema_version"), "missing a string 'schema_version'"),
        (lambda d: d.update(schema_version=1), "missing a string 'schema_version'"),
        (lambda d: d.update(schema_version=None), "missing a string 'schema_version'"),
    ],
)
def test_parser_rejects_missing_or_malformed_versions(
    make_scan_report: Callable[..., ScanReport],
    mutate: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    document = json.loads(render_json(make_scan_report(), exit_code=0))
    mutate(document)

    with pytest.raises(ScanDocumentError, match=message):
        parse_json_document(json.dumps(document))


def test_version_is_checked_before_the_document_shape(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """A future document with an unknown shape reports the version, not a field error."""
    document = _document_with_version(make_scan_report(), "2.0.0")
    document["findings"] = [{"rule_id": "FUTURE-RULE"}]
    document["result"] = {"status": "brand_new_status"}

    with pytest.raises(UnsupportedSchemaVersionError):
        parse_json_document(json.dumps(document), strict=False)


# --------------------------------------------------------------------------------------
# D2: strict vs forward-compatible parsing
# --------------------------------------------------------------------------------------


def test_strict_mode_is_the_default_and_rejects_unknown_members(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    document = json.loads(render_json(make_scan_report(), exit_code=0))
    document["future_member"] = True

    with pytest.raises(ValidationError, match="future_member"):
        parse_json_document(json.dumps(document))


def test_forward_compatible_mode_ignores_unknown_top_level_members(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    report = make_scan_report(findings=[make_finding()])
    document = json.loads(render_json(report, exit_code=1))
    document["future_member"] = {"anything": [1, 2, 3]}

    parsed = parse_json_document(json.dumps(document), strict=False)

    assert parsed.report == report
    assert parsed.result.status is ScanStatus.FINDINGS


def test_forward_compatible_mode_ignores_unknown_result_members(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    document = json.loads(render_json(make_scan_report(), exit_code=0))
    document["result"]["confidence_score"] = 0.87
    document["result"]["future_nested"] = {"a": 1}

    parsed = parse_json_document(json.dumps(document), strict=False)

    assert parsed.result.exit_code == 0
    assert not hasattr(parsed.result, "confidence_score")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["findings"][0].update(future_detail="x"),
        lambda d: d["findings"][0]["location"].update(end_column=7),
        lambda d: d["analyzer_outcomes"][0].update(future_metric=1),
        lambda d: d["discovery"].update(future_counter=4),
    ],
    ids=["finding", "location", "analyzer_outcome", "discovery"],
)
def test_forward_compatible_mode_ignores_unknown_nested_members(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    """Additive MINOR changes inside nested objects must not break a reader."""
    document = json.loads(render_json(make_scan_report(findings=[make_finding()]), exit_code=1))
    mutate(document)

    parsed = parse_json_document(json.dumps(document), strict=False)

    assert parsed.result.status is ScanStatus.FINDINGS


@pytest.mark.parametrize(
    ("mutate", "location"),
    [
        (lambda d: d["result"].update(status="partially_clean"), "status"),
        (
            lambda d: d["result"].update(incomplete_reasons=["future_reason"]),
            "incomplete_reasons.0",
        ),
        (lambda d: d["result"].update(min_severity="blocker"), "min_severity"),
        (
            lambda d: d["analyzer_outcomes"][0].update(status="degraded"),
            "analyzer_outcomes.0.status",
        ),
        (lambda d: d["findings"][0].update(severity="catastrophic"), "findings.0.severity"),
        (lambda d: d["findings"][0].update(category="licensing"), "findings.0.category"),
    ],
    ids=[
        "status",
        "incomplete_reason",
        "min_severity",
        "analyzer_status",
        "finding_severity",
        "finding_category",
    ],
)
def test_forward_compatible_mode_refuses_unknown_values(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
    mutate: Callable[[dict[str, Any]], None],
    location: str,
) -> None:
    """An unrecognized value could change the verdict, so it must never be guessed."""
    document = json.loads(render_json(make_scan_report(findings=[make_finding()]), exit_code=1))
    mutate(document)

    with pytest.raises(UnsupportedSchemaValueError) as captured:
        parse_json_document(json.dumps(document), strict=False)

    assert location in str(captured.value)
    assert "indeterminate" in str(captured.value)


def test_future_status_never_yields_a_clean_verdict(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """Regression for D2: no silent coercion to the nearest known status."""
    document = json.loads(render_json(make_scan_report(), exit_code=3))
    document["result"]["status"] = "unknown_future_status"
    document["result"]["is_complete"] = True

    with pytest.raises(UnsupportedSchemaValueError):
        parse_json_document(json.dumps(document), strict=False)


def test_future_incomplete_reason_never_yields_a_complete_scan(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """Dropping an unknown reason would understate incompleteness, so parsing stops."""
    document = json.loads(render_json(make_scan_report(), exit_code=3))
    document["result"]["incomplete_reasons"] = ["something_new_but_important"]

    with pytest.raises(UnsupportedSchemaValueError):
        parse_json_document(json.dumps(document), strict=False)


def test_forward_compatible_mode_reports_a_non_object_result_member(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    document: dict[str, Any] = json.loads(render_json(make_scan_report(), exit_code=0))
    document["result"] = ["not", "an", "object"]

    with pytest.raises(ScanDocumentError, match="'result' member must be a JSON object"):
        parse_json_document(json.dumps(document), strict=False)


def test_forward_compatible_mode_passes_through_non_object_nested_values(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """A wrong-shaped nested value is left for Pydantic to reject, not silently repaired."""
    document: dict[str, Any] = json.loads(render_json(make_scan_report(), exit_code=0))
    document["discovery"] = "not-an-object"

    with pytest.raises(ValidationError, match="discovery"):
        parse_json_document(json.dumps(document), strict=False)


def test_forward_compatible_mode_still_rejects_structurally_invalid_documents(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """Tolerating unknown members must not turn into tolerating missing required ones."""
    document: dict[str, Any] = json.loads(render_json(make_scan_report(), exit_code=0))
    del document["discovery"]

    with pytest.raises(ValidationError, match="discovery"):
        parse_json_document(json.dumps(document), strict=False)


def test_both_modes_accept_an_unmodified_document(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    document = render_json(make_scan_report(), exit_code=0)

    assert parse_json_document(document) == parse_json_document(document, strict=False)


# --------------------------------------------------------------------------------------
# D3: completeness documentation matches the implementation
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (AnalyzerStatus.FAILED, IncompleteReason.ANALYZER_FAILED),
        (AnalyzerStatus.TIMED_OUT, IncompleteReason.ANALYZER_TIMED_OUT),
    ],
)
def test_failed_and_timed_out_checks_are_incomplete_without_coverage_incomplete(
    make_scan_report: Callable[..., ScanReport],
    status: AnalyzerStatus,
    reason: IncompleteReason,
) -> None:
    """Regression for D3: the README used to claim these set ``coverage_incomplete``."""
    report = make_scan_report(
        outcomes=[AnalyzerOutcome(analyzer_name="ruff-python-lint", status=status)]
    )

    parsed = parse_json_document(render_json(report, exit_code=3))

    assert parsed.result.is_complete is False
    assert parsed.result.incomplete_reasons == [reason]
    assert parsed.report.analyzer_outcomes[0].coverage_incomplete is False


def test_only_started_then_aborted_checks_set_coverage_incomplete(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report(
        outcomes=[
            AnalyzerOutcome(
                analyzer_name="osv-dependency-check",
                status=AnalyzerStatus.UNAVAILABLE,
                coverage_incomplete=True,
            )
        ]
    )

    parsed = parse_json_document(render_json(report, exit_code=3))

    assert parsed.report.analyzer_outcomes[0].coverage_incomplete is True
    assert parsed.result.incomplete_reasons == [IncompleteReason.CHECK_ABORTED]


def test_readme_explains_how_to_judge_completeness() -> None:
    """Guard the D3 correction so the guidance cannot silently regress."""
    readme = _readme()
    section = _json_section(readme)

    assert "### How to tell whether a scan is complete" in section
    assert "`result.is_complete`" in section
    assert "is **not** the general" in section
    assert "coverage_incomplete` is `false` for it" in section
    # The table must attribute the flag to the right rows: failed/timed-out checks are
    # incomplete through their status, not through ``coverage_incomplete``.
    failed_row = _table_row(section, "Analyzer started and then failed or timed out")
    assert "coverage_incomplete: false" in failed_row
    aborted_row = _table_row(section, "Check started, then could not complete")
    assert "coverage_incomplete: true" in aborted_row
    # The old, incorrect prose claim must stay gone.
    assert '`"failed"`/`"timed_out"`) with `coverage_incomplete: true`' not in section


# --------------------------------------------------------------------------------------
# D4: the additive ``result`` member vs. strict 1.0.0 readers
# --------------------------------------------------------------------------------------


def test_strict_report_validator_rejects_the_additive_result_member(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    """Regression for D4: documenting this limitation is the point, not a bug."""
    document: dict[str, Any] = json.loads(render_json(make_scan_report(), exit_code=0))

    with pytest.raises(ValidationError, match="result"):
        ScanReport.model_validate(document)


def test_existing_consumers_can_validate_the_body_without_the_result_member(
    make_scan_report: Callable[..., ScanReport],
) -> None:
    report = make_scan_report()

    document: dict[str, Any] = json.loads(render_json(report, exit_code=0))
    body = {key: value for key, value in document.items() if key != "result"}

    assert ScanReport.model_validate(body) == report


def test_readme_documents_the_strict_reader_limitation() -> None:
    """Guard the D4 correction: the additive member is not invisible to strict readers."""
    section = _json_section(_readme())

    assert "Upgrading from the `1.0.0` report" in section
    assert "Extra inputs are not permitted" in section
    assert "expected, not damage" in section
    assert 'k != "result"' in section


def test_public_exports_cover_the_parsing_contract() -> None:
    import repolens

    for name in (
        "SCHEMA_VERSION",
        "SCHEMA_MAJOR_VERSION",
        "SUPPORTED_SCHEMA_MAJOR_VERSIONS",
        "ScanDocumentError",
        "UnsupportedSchemaVersionError",
        "UnsupportedSchemaValueError",
    ):
        assert name in repolens.__all__
        assert hasattr(repolens, name)


def _readme() -> str:
    return (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")


def _table_row(section: str, first_cell: str) -> str:
    """Return the table row starting with ``first_cell``, through the end of its second cell."""
    start = section.find(f"| {first_cell}")
    assert start != -1, f"README must document the '{first_cell}' case in a table row"
    second_cell_end = section.index("|", section.index("|", start + 2) + 1)
    return section[start:second_cell_end]


def _json_section(readme: str) -> str:
    """Return the JSON output section with prose line wrapping normalised."""
    start = readme.index("## Machine-readable JSON output")
    end = readme.index("## Optional external tools")
    return " ".join(readme[start:end].split())


def test_readme_documents_the_schema_the_code_actually_emits() -> None:
    """The documented example must stay a valid, current document."""
    readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
    block = re.search(r"### Document shape\n\n```json\n(.*?)```", readme, re.S)
    assert block is not None, "README must document the JSON document shape"

    document = json.loads(block.group(1))
    assert list(document) == _EXPECTED_TOP_LEVEL_KEYS
    assert document["schema_version"] == SCHEMA_VERSION

    body = dict(document)
    result = body.pop("result")
    ScanReport.model_validate(body)
    ScanResult.model_validate(result)


def test_report_paths_are_posix_and_repository_relative(
    make_scan_report: Callable[..., ScanReport],
    make_finding: Callable[..., Finding],
) -> None:
    finding = make_finding(path="src/deep/module.py", start_line=3)
    parsed = _loaded(render_json(make_scan_report(findings=[finding]), exit_code=1))

    path = parsed["findings"][0]["location"]["path"]
    assert path == "src/deep/module.py"
    assert "\\" not in path
