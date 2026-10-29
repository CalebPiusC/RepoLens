# ADR-004: Make OSV.dev Network Checks Opt-In Rather Than Default

**Status**: Accepted
**Date**: 2024

---

## Context

The `advisories.py` analyzer queries the OSV.dev batch API (`api.osv.dev/v1/querybatch`) to check whether any dependency resolved in the target repository's lockfiles has a known vulnerability. This check is qualitatively different from all other RepoLens analyzers because it requires an outbound HTTPS connection to an external service.

Running a network request by default raises several concerns:

**Privacy**: The query sends package names, version strings, and ecosystem identifiers to a third-party server. While OSV.dev is a Google-operated open-source database and the data sent is already public (it is the same data in the lockfile), some organisations have policies against any outbound data transmission during automated tooling runs without explicit approval.

**Reliability**: A default network check makes RepoLens's output dependent on network availability and OSV.dev uptime. A flaky network in a CI environment would cause advisory checks to fail, potentially marking builds as incomplete for reasons unrelated to the repository's actual health.

**Air-gapped environments**: Organisations that run CI in air-gapped or network-restricted environments cannot permit outbound HTTPS to arbitrary hosts. A default-on network check would break RepoLens entirely in these environments.

**Unexpected latency**: Even on fast networks, a batch query to an external API adds latency. For users who scan large projects with many dependencies, this latency would be present on every run without the user having made an explicit choice to accept it.

The alternative of making network checks always-on was considered but rejected for all the reasons above. The alternative of removing OSV.dev integration entirely was rejected because vulnerability checking against known advisories is valuable and OSV.dev provides a high-quality, freely available dataset.

---

## Decision

OSV.dev network checks are disabled by default. `ScanConfig.enable_network_checks` defaults to `False`. When `False`, the `advisories.py` analyzer records its outcome as `skipped` with a clear message indicating that network checks are not enabled.

Users who want vulnerability advisory checking must explicitly pass `--network-checks` on the CLI, or set `enable_network_checks=True` in a programmatic `ScanConfig`. This makes the decision to transmit data to an external service visible and deliberate.

When network checks are enabled, the implementation enforces additional constraints:

- Only HTTPS is permitted; HTTP URLs are rejected.
- HTTP redirects are not followed.
- Response size is capped.
- A request timeout is applied.
- The payload contains only `name`, `version`, and `ecosystem` fields; no file content or repository metadata is transmitted.

---

## Consequences

**Positive**:

- RepoLens works correctly with no network access in its default configuration.
- Organisations with data transmission policies or air-gapped environments can use RepoLens without any configuration change.
- The decision to send data to OSV.dev is explicit and auditable in CI configuration.
- Network-related flakiness cannot affect scans that do not opt in.

**Negative**:

- Users who want vulnerability checks must remember to pass `--network-checks`. The default output will not include advisory findings, which could give a false sense of completeness if users do not read the analyzer outcome section of the report.
- The opt-in flag must be documented prominently in the README and help text to ensure it is discoverable.
