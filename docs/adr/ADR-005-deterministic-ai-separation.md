# ADR-005: Keep Deterministic Findings Strictly Separate from AI Advisories

**Status**: Accepted
**Date**: 2024

---

## Context

RepoLens's roadmap includes a Stage 4 feature: opt-in Gemini-powered advisory explanations. These would use a large language model to provide richer context, suggested remediation steps, or code-level guidance for findings that the deterministic analyzers produce.

A key design question is whether AI-generated content should be merged into the existing `Finding` model or kept in a separate model (`AIAdvisory`).

**Arguments for merging**: A single unified finding type would simplify the report schema. Consumers (CLI renderer, future API clients) would not need to handle two different types.

**Arguments for separation**: Several properties of deterministic findings do not apply to AI-generated content and cannot be safely attributed to it:

- **Reproducibility**: Deterministic findings are stable across runs given the same input. LLM outputs are not. Merging them would make the combined finding non-reproducible.
- **Fingerprinting**: Each `Finding` has a SHA-256 fingerprint derived from its stable fields. This fingerprint is used for deduplication and for tracking findings across scans. An AI-generated explanation field would either be excluded from the fingerprint (making it vestigial) or included (making the fingerprint unstable).
- **Trust level**: Deterministic findings are verifiable: a reviewer can inspect the rule logic and confirm the finding is correct. An AI advisory is a probabilistic suggestion. Mixing the two in the same type implies a false equivalence in trustworthiness.
- **Opt-in semantics**: AI advisories are opt-in (they require a Gemini API key and explicit enablement). Deterministic findings are always produced. Merging the two would complicate the opt-in logic and potentially suppress deterministic findings when AI enrichment is not available.
- **Auditability**: Regulated environments may require that automated security findings be fully deterministic and traceable to a rule. AI-generated content cannot satisfy this requirement. Separate types allow consumers to use only `Finding` objects in such contexts and ignore `AIAdvisory` objects entirely.

---

## Decision

`Finding` and `AIAdvisory` are distinct Pydantic models. `ScanReport` contains two separate lists: `findings: list[Finding]` and `ai_advisories: list[AIAdvisory]`. The `Finding.source` field is always set to `"deterministic"`. No `Finding` object is ever populated with AI-generated content.

`AIAdvisory` objects may reference a `Finding` by its `fingerprint` to provide supplementary explanation, but they do not replace or modify the `Finding`.

The Stage 4 Gemini integration will populate `ai_advisories` without touching `findings`. Consumers that do not enable AI features receive an empty `ai_advisories` list and a fully valid report.

---

## Consequences

**Positive**:

- Deterministic findings remain reproducible and fingerprintable regardless of whether AI features are enabled.
- The report schema is honest about the provenance and trust level of each piece of content.
- Regulated or audit-focused consumers can rely on `findings` exclusively and ignore `ai_advisories` without loss of correctness.
- The AI integration layer can evolve independently of the core finding model.
- Testing of the deterministic analyzers does not require any AI API or mock.

**Negative**:

- Report consumers must handle two types rather than one. The CLI renderer and any future API client must be aware of both.
- The separation introduces a level of indirection: an `AIAdvisory` that references a `Finding` by fingerprint creates a join that consumers must resolve if they want to display enriched findings.
- Documentation must clearly explain the distinction to avoid confusion for users who expect AI-enhanced findings to appear in the main findings list.
