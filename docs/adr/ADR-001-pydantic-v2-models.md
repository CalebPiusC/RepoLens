# ADR-001: Use Pydantic v2 for All Data Models

**Status**: Accepted
**Date**: 2024

---

## Context

RepoLens produces structured data at several layers: discovered file metadata, individual findings, per-analyzer outcomes, and the top-level scan report. This data must be:

- Validated at construction time so that invalid states are impossible to represent.
- Serialisable to JSON for future API and web interface stages.
- Typed precisely enough for `mypy --strict` to verify correctness throughout the codebase.
- Immutable after construction so that reports cannot be accidentally mutated by downstream consumers.

Several approaches were considered:

1. Plain Python dataclasses with manual validation.
2. `attrs` with validators.
3. Pydantic v1.
4. Pydantic v2.

Plain dataclasses require entirely manual validation logic and have no built-in serialisation. `attrs` provides good validation but less complete JSON serialisation. Pydantic v1 is well understood but is end-of-life and slower than v2 for validation-heavy workloads. Pydantic v2 provides a Rust-backed validation core, a clean migration from v1 patterns, first-class `model_config` for immutability, and JSON schema generation that will be needed at Stage 5 (FastAPI web interface).

---

## Decision

All data models in RepoLens use Pydantic v2. Models are defined in `models.py` using `BaseModel` with `model_config = ConfigDict(frozen=True)` where immutability is required. Validators use the `@field_validator` and `@model_validator` decorators from Pydantic v2.

`ScanConfig` (in `config.py`) is also a Pydantic model, giving it the same validation and serialisation properties as the output models.

---

## Consequences

**Positive**:

- All model fields are validated at construction time. Invalid field values raise a `ValidationError` immediately rather than propagating silently.
- `model.model_dump()` and `model.model_dump_json()` provide zero-effort serialisation for future API integration.
- JSON schema can be generated from models without additional code, enabling OpenAPI documentation at Stage 5.
- `mypy --strict` can verify that all model fields are used correctly because Pydantic v2 ships a mypy plugin.
- Frozen models (`frozen=True`) prevent accidental mutation of `ScanReport` objects after construction.

**Negative**:

- Pydantic v2 is a required runtime dependency. Projects embedding RepoLens as a library must accept this dependency.
- The Pydantic v2 API differs from v1 in ways that require attention during upgrades. Contributors must use v2 patterns (e.g., `model_config`, `@field_validator` with `mode='before'`) and not v1 patterns.
- Pydantic's validation overhead is measurable for very large collections of findings, though in practice the number of findings per scan is bounded by `max_findings`.
