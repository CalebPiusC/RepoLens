# ADR-005: Keep Deterministic Findings Strictly Separate from AI Advisories

**Status:** Accepted
**Recorded:** 2026-10-29, retrospectively (separation implemented in Stage 1 models, October
2026; the Stage 4 AI feature itself is not implemented)

## Context

The roadmap's Stage 4 proposes opt-in, Gemini-generated explanations. Deterministic findings are
reproducible, rule-traceable, and fingerprint-stable (each `Finding.fingerprint` is a truncated
SHA-256 over `source.tool`, `rule_id`, `category`, location, and `title`, used for deduplication
and sorting). LLM output is none of those things, requires an API key and explicit opt-in, and
cannot meet audit expectations for security findings. Merging both into one type would either
destabilize fingerprints/verdicts or falsely imply equal trust.

## Decision

`Finding` and `AIAdvisory` are distinct frozen models, enforced by validators:

- `Finding.source` is a `FindingSource` whose `kind` must be `SourceKind.DETERMINISTIC`
  (`"deterministic"`); constructing a `Finding` from an AI source raises `ValidationError`.
- `AIAdvisory.source.kind` must conversely be `AI_ADVISORY`. Advisories reference findings via
  `related_finding_fingerprints: list[str]`; they never replace or mutate findings.
- `ScanReport` carries `findings: list[Finding]` and `ai_advisories: list[AIAdvisory]` separately.
  Exit codes and `result` semantics consider findings only. Both lists are part of the JSON
  document (ADR-006); consumers who do not enable future AI features will see an empty
  `ai_advisories` array and a fully valid report.

## Consequences

Positive:

- Deterministic findings, fingerprints, and verdicts are unaffected by whether AI features exist
  or are enabled; audit-oriented consumers can ignore `ai_advisories` entirely; deterministic
  analyzers need no AI mocks to test.

Negative:

- Consumers handle two item types and must join advisories to findings by fingerprint to render
  enriched output; documentation must keep the distinction explicit so AI text is never mistaken
  for a confirmed finding.
