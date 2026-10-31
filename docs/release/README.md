# First PyPI release

The tag-only [publishing workflow](../../.github/workflows/publish.yml) is release infrastructure,
not authorization to publish. The current source remains `0.1.1.dev1`; it is rejected by the
workflow. The intended first final version is `0.1.1`. The JSON schema remains `1.1.0` and is
versioned separately. See the [draft changelog](../changelog/README.md).

## Owner-side setup required before a release

These settings are controlled by the repository and PyPI owners, not by this workflow:

1. **Protect `main` and release tags.** Require the existing quality and installation checks and
   human review before merging release changes. During this review the `Protect main` ruleset was
   active and required a PR approval, but its required-status-check list was empty. The `Protect
   releases` ruleset for `v*` tags was disabled. Enable and verify appropriate tag creation,
   update, deletion, and bypass restrictions before allowing publication.
2. **Protect the `pypi` environment.** It already exists with a required reviewer and self-review
   prevention, but no deployment branch/tag restriction was configured during this review. Limit
   deployment to the intended protected `v*` tags. Ensure an authorized reviewer distinct from
   the tag-pushing actor can approve: self-review is disabled and only one reviewer was listed.
   Review any administrator bypass permissions. Keep private vulnerability reporting enabled or
   document another authorized private channel.
3. **Configure PyPI Trusted Publishing.** Once this workflow is merged and the protections are
   verified, an authorized PyPI account owner should register a
   [pending publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
   for project `repolens`, owner `CalebPiusC`, repository `RepoLens`, workflow filename
   `publish.yml`, and environment `pypi`. The environment name is essential: the separate build
   job requests an OIDC token for GitHub provenance but must not be trusted to publish to PyPI.
   Do not configure a second publisher that omits the environment constraint. No long-lived PyPI
   token or password is needed in repository or environment secrets.

The PyPI project endpoints returned 404 during review on 2026-10-31, but that does not reserve the
name or prove it was never previously used. Account-side publisher configuration was not verified.
Recheck the normalized name, ownership, and release records immediately before release.
TestPyPI, if separately authorized later, needs its own account, project, publisher, environment,
audience, and destination; this workflow publishes only to production PyPI.

## How the workflow protects a release

Only a push of a `v*` tag can start the workflow; branch pushes and pull requests cannot publish.
Both jobs require the upstream repository, a tag-push event, and a tag still resolving to the event
commit. The checked-out commit must be reachable from `origin/main`. The tag must exactly match
`v<version>`, where the static package version is a canonical final `N.N.N` version: development,
pre-release, post-release, and local versions are rejected. Tag restrictions and `main` protection
are still necessary: someone who can change the tagged workflow or bypass environment approval
can bypass checks in that workflow.

The build job checks the README's pending-PyPI text and version example, fails closed if PyPI's
version endpoint is not a direct 404, and creates one canonical wheel and sdist. It runs
`twine check --strict`, verifies archive allowlists, metadata, source bytes and wheel RECORD hashes,
and exercises fresh installs of both distributions with the existing lifecycle checks. It records
their SHA-256 hashes, generates GitHub build-provenance attestations, verifies the files again, and
uploads them as one internal workflow artifact. These are not PyPI uploads.

After the `pypi` environment is approved, the publish job checks the tag and main ancestry again,
downloads that artifact by ID, verifies the exact two filenames and hashes, and checks PyPI again
immediately before publishing those same files. It never rebuilds. Runs are serialized and
`skip-existing` is disabled. A 404 cannot prove a deleted version was never used, and the check is
not atomic with an outside publisher; review the owner's release history. PyPI's immutable
filenames provide an additional safeguard, not a substitute for that review.

The build job's `id-token: write` and `attestations: write` permissions are for GitHub build
provenance and are outside the PyPI-trusted environment. Only the protected publish job receives an
OIDC token usable by its exactly configured PyPI publisher. The PyPA action also generates
[PyPI Publish attestations](https://docs.pypi.org/attestations/producing-attestations/) for the
uploaded files. They identify the publisher and file digests; they are **not** the GitHub build
provenance attestation. Neither proves a hermetic build or a security audit.

## Preparing and approving the first release

Perform these steps only after separate release approval:

1. In a reviewed release change, set `src/repolens/_version.py` to `0.1.1`. Update the CLI version
   example and replace the README's pending-PyPI claims with wording that is accurate both before
   and after upload, such as how to install **an available** release; do not claim it is already
   published. Update the tests enforcing pending-PyPI wording and any affected security/version
   documentation. Keep schema `1.1.0`. Do not mark the changelog as released before publication.
2. Run all quality checks, the Linux/Windows installation matrix, and artifact inspection on that
   change. Merge only after the owner-required approvals and checks pass. Confirm that the release
   commit is on protected `main`, the version has never been published, and the owner-side setup
   above is complete.
3. An authorized tag creator can create and push the immutable tag on that reviewed commit:

   ```sh
   git fetch --no-tags origin main
   # Replace with the reviewed release commit, verified reachable from origin/main.
   RELEASE_COMMIT=<full-release-commit-sha>
   git merge-base --is-ancestor "$RELEASE_COMMIT" origin/main
   git tag -a v0.1.1 "$RELEASE_COMMIT" -m "RepoLens 0.1.1"
   git push origin refs/tags/v0.1.1
   ```

   Pushing the tag starts the workflow. Do not create a tag, GitHub release, or publication until
   explicitly authorized; these are separate actions.
4. Inspect the build job, the exact candidate hashes, its provenance, and the existing CI results.
   A different authorized reviewer then approves the pending **pypi** deployment in the GitHub
   Actions run. Approval releases the publish job; it does not create a GitHub release.

## Verify after an authorized publication

Only after the workflow reports successful publication, check the PyPI project and files, compare
both SHA-256 hashes with the workflow, and install the exact version in a fresh environment:

```sh
python -m venv /tmp/repolens-release-verify
. /tmp/repolens-release-verify/bin/activate
python -m pip install 'repolens==0.1.1'
python -m pip check
repolens --version
repolens --help
# Run `repolens scan .` in a separate test project, not the virtual environment.
```

Download both files from PyPI, compare their hashes with the workflow, and use a current GitHub
CLI to verify each file's GitHub build provenance against the repository, workflow, and tag:

```sh
mkdir -p /tmp/repolens-published
python -m pip download --no-deps --only-binary=:all: 'repolens==0.1.1' -d /tmp/repolens-published
python -m pip download --no-deps --no-binary=:all: 'repolens==0.1.1' -d /tmp/repolens-published
cd /tmp/repolens-published
sha256sum repolens-0.1.1-py3-none-any.whl repolens-0.1.1.tar.gz
gh attestation verify repolens-0.1.1-py3-none-any.whl \
  --repo CalebPiusC/RepoLens \
  --signer-workflow CalebPiusC/RepoLens/.github/workflows/publish.yml \
  --source-ref refs/tags/v0.1.1
```

Repeat for `repolens-0.1.1.tar.gz` and inspect the corresponding PyPI Publish attestations separately.
These checks do not assert that PyPI's publish attestation itself is build provenance.

## Failure and recovery

- If validation, provenance, approval, or a transient service fails **before any file is uploaded**,
  inspect the run and PyPI/release history. Fix account settings or transient problems, then rerun
  only after confirming no file for that version exists. If source changes are needed, use a new
  reviewed commit and version/tag rather than moving or reusing a protected tag.
- If one file was uploaded or the version already exists, stop: this workflow intentionally
  refuses to continue or skip existing files. The PyPI owner should inspect the partial release,
  coordinate any yanking, and choose a new version after review. Deleting a file does not make its
  filename reusable. Do not try to replace artifacts or silently complete a partial upload.
- If Trusted Publishing fails, verify the exact PyPI owner/repository/workflow/environment tuple,
  environment approval and tag restrictions, and PyPI's project-name ownership before retrying.
  Do not add a long-lived token as a workaround.
