# ADR-006: Emit One Versioned JSON Document (`--format json`, Schema `1.1.0`)

**Status:** Accepted
**Recorded:** 2026-10-29 (implemented on `main` in "feat: add versioned JSON scan output" and
"fix: harden JSON schema compatibility handling")

## Context

CI and tooling consumers need machine-readable results without parsing the terminal table, and
without re-implementing RepoLens's exit-code/incompleteness policy (where the subtle cases —
never-available vs started-then-aborted checks, partial coverage, discovery truncation — are easy
to get dangerously wrong by reading a scan as "clean"). A second, hand-maintained JSON schema
would drift from the report models. There were also no stability rules for the serialized shape:
`ScanReport.schema_version` existed as an unvalidated `"1.0.0"` literal.

## Decision

- `repolens scan --format {text,json}` (default `text`). JSON mode writes exactly one document to
  stdout — no banner, color, or progress text at any `--color` setting — while diagnostics stay
  on stderr. If no report is produced (usage/operational errors, interrupts), stdout stays empty.
  Exit codes are identical across formats.
- The document body is `ScanReport.model_dump(mode="json")`; serialization adds **one** member,
  `result` (`ScanResult`), derived by `json_output.build_scan_result()` from the same
  `reporting.evaluate()` verdict that drives the terminal Result line and
  `cli.determine_exit_code()`. The caller's exit code is passed in, never recomputed, so document
  and process status cannot disagree. Implementation: `repolens.json_output`
  (`render_json`, `build_json_document`, `build_scan_result`) using only the standard library.
- JSON always contains **every** finding. `--max-findings` remains a text-table presentation
  limit; `--min-severity` affects only the verdict fields (`result.has_findings`, `status`,
  counts at/above threshold), not document completeness.
- `SCHEMA_VERSION = "1.1.0"` (in `models.py`, shape-validated with `validate_default=True`)
  versions the *document shape*, independently of `repolens_version`. The `1.0.0` → `1.1.0` bump
  is MINOR because it is purely additive (the `result` member plus documented ordering/encoding
  guarantees; no `1.0.0` field was renamed, removed, or re-typed). Removal/rename/retype/meaning
  changes require MAJOR; documentation-only changes are PATCH.
- Reading is a supported operation: `json_output.parse_json_document()` validates the body and
  `result` separately (a bare `ScanReport` dump without `result` is rejected with
  `ScanDocumentError`, never silently completed). Version acceptance is by major version
  (`SUPPORTED_SCHEMA_MAJOR_VERSIONS`): any minor/patch of a supported major is accepted as a
  version; another major raises `UnsupportedSchemaVersionError`. With `strict=False`, unknown
  *members* are ignored anywhere in the graph, but unknown *values* for known members still stop
  parsing with `UnsupportedSchemaValueError` — guessing a verdict value could turn an incomplete
  scan clean. Strict mode (default) rejects both. All scan-document errors subclass `ValueError`.
- Determinism: for the same content/options the document is byte-identical except `scanned_at`
  and `duration_ms` values — fixed member order, engine finding order, enum-ordered zero-inclusive
  count maps, ASCII-only bytes (`ensure_ascii=True`, `allow_nan=False`), UTC `Z` timestamps,
  POSIX relative paths, explicit `null`s.

The normative contract lives in the README's "Machine-readable JSON output"; this ADR records why
it has this shape.

## Consequences

Positive:

- One source of truth: JSON cannot drift from the models or from the exit-code policy; consumers
  read `result.is_complete`/`result.status` instead of re-deriving false-clean logic.
- Forward compatibility is explicit and safe-direction: additive changes are tolerable, semantic
  unknowns fail loudly as "indeterminate".
- No new dependencies; redaction and all discovery/subprocess guarantees apply unchanged because
  the document is serialized from the same already-redacted models.

Negative:

- Strict `1.0.0`-era readers using `ScanReport.model_validate` on a whole CLI document now fail
  on the extra `result` member (`extra="forbid"`); the README documents the three migrations
  (maintained parser, body-only validation, `strict=False`).
- Schema discipline is now a compatibility obligation: model/enum changes must be reviewed for
  version bumps, and forward-compatible parsing (member projection across nested models and
  containers) needs dedicated tests (`tests/unit/test_json_output.py`).
