# ADR-001: Use Pydantic v2 for All Data Models

**Status:** Accepted
**Recorded:** 2026-10-29, retrospectively (implemented in Stage 1, October 2026)

## Context

RepoLens produces structured data at several layers: discovery summaries, findings, per-analyzer
outcomes, and the top-level scan report. This data must be validated at construction, precisely
typed for `mypy` strict mode, immutable after construction, and serializable — the same models
back the library API, the terminal reporter, and (since ADR-006) the versioned JSON document, and
are intended to serve the planned Stage 5 web interface without a parallel schema.

Alternatives in this space (plain dataclasses with manual validation, `attrs`, Pydantic v1) trade
away some combination of built-in validation, JSON serialization/schema generation, and typing
integration. Pydantic v1 is additionally end-of-life.

## Decision

All data models use Pydantic v2 (`pydantic>=2.7,<3.0`): the report models in `models.py`
(`Finding`, `AIAdvisory`, `AnalyzerOutcome`, `DiscoverySummary`, `ScanReport`, `ScanResult`, and
their supporting types) and `ScanConfig` in `config.py`. Models set
`model_config = ConfigDict(extra="forbid", frozen=True)`; validation uses v2 `@field_validator` /
`@model_validator` (for example evidence redaction and fingerprint generation on `Finding`). The
Pydantic mypy plugin is enabled in `pyproject.toml`.

## Consequences

Positive:

- Invalid states fail at construction with `ValidationError` instead of propagating.
- `model_dump(mode="json")` is the single serialization path; the JSON reporter reuses it
  verbatim (ADR-006), and JSON Schema generation comes for free for future API work.
- Frozen models prevent accidental mutation of a completed `ScanReport`.

Negative:

- Pydantic is a required runtime dependency for anyone embedding RepoLens as a library.
- Contributors must use v2 idioms (`model_config`, v2 validator signatures); v1 patterns will not
  type-check.
- Validation cost grows with finding count; in practice this is bounded per analyzer by
  `ScanConfig.max_findings_per_analyzer` (default 200). The CLI's `--max-findings` is a separate
  terminal-rendering cap and does not bound model construction.
