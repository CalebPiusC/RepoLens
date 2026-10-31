# First PyPI release readiness

This is a preparation checklist, **not a publishing workflow or authorization to release**.
There are no RepoLens tags, GitHub releases, or PyPI uploads. The preparation revision is
`0.1.1.dev1`; the intended first stable package version is `0.1.1`. The JSON schema remains
`1.1.0` and is not derived from the package version. See the [draft notes](../changelog/README.md).

## Blockers and decisions checked on 2026-10-31

- The PyPI JSON and simple-index endpoints for `repolens` returned 404 during preparation on
  2026-10-31. This is not a reservation or a guarantee of availability; the name may be taken
  before release. No PyPI or TestPyPI account-side publisher configuration was verified.
- There is no publishing workflow or GitHub environment in the repository. Main-branch protection
  settings could not be read with the available integration. The owner must verify required
  reviews and checks, and restrict release-tag creation or modification.
- GitHub private vulnerability reporting is disabled, and no other private contact is documented.
  The owner must enable it or add an authorized private reporting channel before release.
- The installation matrix builds and tests artifacts on each runner and also installs the same
  hash-verified CI build on Linux and Windows. It does **not** promote those artifacts to PyPI and
  is not a release provenance system.
- `0.1.1.dev0` was already downloadable from source and must not be published. This revision
  advances to `0.1.1.dev1`, also unpublished; `0.1.1` is reserved for a separately approved
  stable release. Do not replace published artifacts or reuse a published version.

## Before creating an actual release

1. Complete human review, merge the preparation work only with separate approval, and require the
   existing quality and Linux/Windows installation checks on protected `main`. Address failures,
   the private-reporting blocker, and any newly discovered release-critical issues first. CI is
   evidence for the tested revisions and platforms, not a substitute for review or a security audit.
2. In a reviewed future release change, set the sole package version in
   `src/repolens/_version.py` to `0.1.1`; preserve the independently versioned schema `1.1.0`.
   Update the CLI version example and make the packaged README's PyPI instructions truthful both
   before and after publication: remove time-dependent "not published"/"currently fails" claims
   and describe how to install **an available** release without claiming one already exists.
   Update the tests that currently enforce the pending-PyPI wording. Do not mark these draft notes
   as released or announce a release before publication actually succeeds.
3. Have the repository owner set up a reviewed, protected GitHub environment named `pypi` with
   required human approval, and restrict release tags using repository rules. The proposed future
   workflow filename is `.github/workflows/publish.yml`; it does not exist yet. After the workflow
   and environment are approved, an authorized PyPI account owner can configure a
   [pending trusted publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
   for project `repolens`, owner `CalebPiusC`, repository `RepoLens`, workflow `publish.yml`, and
   environment `pypi`. Recheck the normalized name and ownership immediately before release: a
   pending publisher does not reserve a new project name.
4. Only after separate authorization, create the protected `v0.1.1` tag on the reviewed release
   commit and run the approved release workflow. Verify the artifact versions, tag and commit,
   checks, approvals, and destination before uploading. A tag, GitHub release, PyPI publication,
   and announcement are distinct actions; none is automatic or implied by this checklist.

## Recommended minimal workflow, to be implemented and reviewed later

Use a manually dispatched workflow tied to a protected version tag; do not publish on pushes or
pull requests. Require its checked-out tag to resolve to a commit reachable from protected `main`,
and reject arbitrary branches. Check that the exact `v<version>` tag matches the single source
version and both distributions' metadata, that the version is a final PEP 440 release (no dev,
pre-release, or local suffix for production), and that the intended version is `0.1.1` for this
first release. Check existing versions through PyPI and the owner's release records: stop on an
existing or uncertain version, a network error, or an unexpected response. A 404 alone does not
prove a previously deleted version was never used. Never use `--skip-existing` to hide a partial
or duplicate upload; PyPI's filename immutability is a final safeguard, not a replacement for
this check.

Build one canonical wheel and sdist from the clean tagged commit. Run strict metadata checks,
archive allowlist/secret review, and the existing quality and installation tests against **those
same artifacts**, including Linux and Windows. An optional second build can verify reproducibility,
but must not become a second release candidate. Store the canonical files and their SHA-256
manifest as an immutable workflow artifact; use the artifact ID for handoff, recheck the digests
before upload, and publish exactly those files without rebuilding. Pin third-party actions to
reviewed full commit SHAs, minimize job permissions, and do not expose publication credentials to
build or test jobs.

Use [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/) with
short-lived OIDC credentials, not a long-lived API token. Only the protected publish job needs
`id-token: write` for PyPI; approval must gate that job, which should only download and verify the
chosen artifacts and invoke the pinned official PyPA publishing action. Register the exact
workflow and `pypi` environment with PyPI. If adding GitHub build-provenance attestation in a
separate build job, grant only the permissions that action requires, including `id-token: write`
and `attestations: write`; keep that job outside the PyPI-trusted environment and verify its
subject digests and source commit. The PyPA action's default
[PyPI Publish attestation](https://docs.pypi.org/attestations/producing-attestations/) identifies
the publisher and artifact digest; it is **not** SLSA build provenance and does not by itself
prove how the files were built. Neither attestation alone proves a hermetic build or a security
audit.

A separately authorized TestPyPI rehearsal, if desired, needs its own account, project-name check,
pending publisher, protected environment, and TestPyPI audience/destination. It must not reuse or
fall back to production credentials. No TestPyPI or PyPI upload is performed by this checklist.
