# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). RepoLens has no
tagged or published release. The JSON document schema is independently versioned at `1.1.0`.

## [Unreleased] — intended first stable release: 0.1.1

These are draft notes, not a release announcement. This preparation revision is `0.1.1.dev1`;
the preceding `0.1.1.dev0` was downloadable from source but was not published to PyPI. A stable
`0.1.1` version, tag, and publication require separate approval.

### First-release scope

The following capabilities were already present in the last `0.1.0` development baseline
([`f4c0f46`](https://github.com/CalebPiusC/RepoLens/commit/f4c0f46c475135f9116afb6469b216cb4ebf02bd));
that baseline was not a tagged or published release:

- Repository structure, Python and JavaScript/TypeScript, dependency hygiene, documentation, and
  testing checks. Ruff, Bandit, and Biome are external tools when installed; OSV.dev vulnerability
  lookups are explicitly opt-in.
- A `repolens scan` CLI with terminal, deterministic JSON, and self-contained HTML output;
  documented exit codes and incomplete-scan reporting. The JSON schema remains `1.1.0`.
- Discovery and subprocess safeguards for scanning untrusted repositories, resource limits, and
  redaction. See the [security model](../security/README.md) for boundaries and limitations.

### Changes since the `0.1.0` development baseline

- Single-source PEP 440 package versioning, reproducible wheel and sdist configuration, and
  complete distribution metadata; the distribution, import, and executable are all `repolens`.
- Installation, upgrade, optional-tool, and uninstall guidance, including the distinction between
  same-version source reinstalls and upgrades to a new version.
- Linux and Windows non-editable artifact and source installation checks on Python 3.11–3.13,
  including real scans, dependency checks, and uninstall cleanup. The supported minimum is 3.11;
  macOS is not currently covered by CI.
- The preparation revision advances to `0.1.1.dev1` to distinguish it from the downloadable
  `0.1.1.dev0` source. No package behavior or JSON schema change is implied by this version bump.

The [release readiness checklist](../release/README.md) records the remaining publishing and
private vulnerability reporting prerequisites. Nothing in these notes implies a tag or upload.
