# ADR-004: Make OSV.dev Network Checks Opt-In Rather Than Default

**Status:** Accepted
**Recorded:** 2026-10-29, retrospectively (implemented in Stage 2, October 2026)

## Context

The advisories analyzer (`analyzers/advisories.py`, `name = "osv-dependency-check"`) queries
OSV.dev for known vulnerabilities in locked dependencies. It is the only analyzer needing outbound
HTTPS. Default-on network access would: transmit lockfile coordinates to a third party without an
explicit choice; make scan results depend on network/service availability (flaky CI could turn
incomplete for reasons unrelated to the repository); break air-gapped environments; and add
latency to every scan. Removing OSV integration entirely would drop genuinely useful signal.

## Decision

Network checks are off by default: `ScanConfig.enable_network_checks` defaults to `False`, and
the CLI enables it only via `--network-checks`. When disabled — and the repository actually has
locked packages, so the analyzer is applicable — the outcome is `skipped` with an explanatory
message; with no locked packages it is `skipped` as not applicable. Either way the analyzer table
shows that no lookup happened.

When enabled (`osv.py`): HTTPS only to the fixed `api.osv.dev` origin, redirects rejected,
validated paths, per-request + total timeouts, response-size cap, batches of 100, package and
advisory caps, and payloads limited to package `name`, `version`, and `ecosystem`. Failures after
the lookup starts make coverage incomplete (timeout → `timed_out`; network/HTTP error →
`unavailable` with `coverage_incomplete`; unreadable payload → `failed`) — because the user
explicitly requested the check, it is never reported as a benign "tool not installed".

## Consequences

Positive:

- Default scans work fully offline, including in air-gapped CI; the decision to transmit
  coordinates is visible in the invocation; network flakiness cannot affect non-opted-in scans.

Negative:

- Vulnerability findings require remembering `--network-checks`; users who do not read the
  analyzer outcomes may overestimate a default scan's coverage. The flag is therefore documented
  in CLI help, the README, and this ADR.
