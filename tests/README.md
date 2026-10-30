# Test Suite

How the tests are organized, what they assume, and how to run subsets. Setup uses `pip` in a
virtual environment (there are no Hatch environments configured; see
[docs/contributing/README.md](../docs/contributing/README.md)):

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Layout

```text
tests/
  conftest.py      Shared fixtures (below)
  unit/            Module/behavior tests in isolation
  integration/     End-to-end pipeline and installed-entry-point tests
  security/        Threat-boundary tests: symlink safety, no target-code
                   execution, subprocess isolation, redaction
```

### Shared fixtures (`conftest.py`)

| Fixture | Purpose |
| --- | --- |
| `_clear_tool_availability_cache` (autouse) | Prevents cached external-tool probes leaking between tests. |
| `make_python_repo` / `make_jsts_repo` | Minimal healthy Python / TypeScript repository trees under `tmp_path`, with include/exclude knobs (license, readme, gitignore, manifests, tests, lockfiles). |
| `install_fake_tool` | Creates a stub `ruff`/`bandit`/`biome` executable (a Python implementation behind a native launcher: a `.cmd` shim on Windows, a shell wrapper elsewhere) in a temp bin directory and puts it on `PATH`, so tests exercise the real subprocess path without the real tools. |
| `make_symlink` | Creates symlinks, skipping cleanly where the host forbids it (see Windows notes). |
| `short_root`, `make_nested_directories` | Short scratch roots and deep trees for the 64-level depth-limit tests. |
| `make_finding`, `make_scan_report` | Valid `Finding`/`ScanReport` factories for reporting, CLI, and JSON tests. |

### `unit/`

One file per module or cohesive behavior area. Current files:

| File | Area |
| --- | --- |
| `test_advisories_analyzer.py` | OSV analyzer incl. opt-in, caps, and incomplete-coverage failure modes |
| `test_biome_analyzer.py` | Biome output parsing and severity/category mapping |
| `test_cli.py` | Argument parsing, exit codes, text/JSON dispatch via a fake engine |
| `test_dependencies.py` | Manifest/lockfile parsing into the dependency inventory |
| `test_dependency_analyzer.py` | `RL-DEP-*` rules |
| `test_discovery_failures.py` | Unreadable entries, caps, depth limits |
| `test_docs_and_testing.py` | `RL-DOC-*` and `RL-TEST-*` rules |
| `test_engine.py` | Engine lifecycle — including `test_repolens_repository_passes_self_scan`, which scans this repository itself |
| `test_engine_stage2.py` | Stage 2 lifecycle cases (skips, unavailability, partial coverage) |
| `test_json_output.py` | JSON document shape, determinism, `result` semantics, schema-version acceptance, strict/forward-compatible parsing |
| `test_models.py` | Pydantic model validation, fingerprints, redaction-at-entry |
| `test_osv.py` | OSV.dev client against mocked transports (no live network) |
| `test_python_analyzers.py` | Ruff/Bandit parsing and severity mapping |
| `test_reporting.py` | Terminal rendering and verdict evaluation |
| `test_structure_analyzer.py` | `RL-STRUCT-*` / `RL-SEC-001` rules |
| `test_tooling.py` | Tool probing, file selection, workspaces, path mapping |

### `integration/`

| File | What it proves |
| --- | --- |
| `test_cli_entry_point.py` | The installed `repolens` console script (or `python -m repolens`) in a real subprocess: packaging, stdout/stderr behavior in both formats, real exit codes. |
| `test_stage2_scan.py` | The full default analyzer suite over fixture repositories with stubbed tools, end to end through `ScanEngine`. |

### `security/`

Kept separate so the threat-boundary guarantees are easy to find and run alone
(`pytest tests/security`):

| File | Invariants |
| --- | --- |
| `test_discovery_safety.py` | Symlinks never followed, symlinked root rejected, post-discovery symlink swap refused by `read_text`, sensitive contents never read, caps enforced |
| `test_stage2_safety.py` | A full scan never executes target-repository code, scripts, or configuration |
| `test_subprocess_and_redaction.py` | `shell=False`, allowlisted child environment, whole-tree timeouts, secrets redacted from evidence/messages |

## Markers

One custom marker is registered in `pyproject.toml` (with `--strict-markers`):

| Marker | Meaning |
| --- | --- |
| `network` | *Documentation of the network boundary:* tests that exercise the OSV.dev client **against a mocked transport**. No test currently carries this marker and nothing calls live services, so `pytest -m network` collects nothing today, and the default run neither needs nor performs network access. Do not describe these as skipped-by-default live tests. |

All other markers in use are built-ins (`parametrize`, `skipif` for platform capabilities).

## Running tests

```bash
pytest                                        # everything
pytest --cov=repolens --cov-report=term-missing
pytest tests/unit                             # one directory (or tests/integration, tests/security)
pytest tests/security/test_discovery_safety.py  # one file
pytest -k test_symlink_repository_root_is_rejected  # one test by name
pytest -v                                     # verbose
```

## Environment assumptions

- **Not required:** Ruff, Bandit, Biome, Node.js, network access, root/administrator rights, or
  Docker. Tools are stubbed via `install_fake_tool`; OSV.dev is replaced with in-memory
  transports.
- **Windows capabilities are handled by skipping, never by weakening assertions:** symlink tests
  skip when the host cannot create symlinks (unprivileged Windows without Developer Mode; the CI
  Windows runner can); depth-limit tests nest single-character directories under a short scratch
  root and skip if the filesystem still refuses (~260-char path limits); directory-permission
  tests skip where `chmod` is not enforced (Windows).
- CI runs the suite on Ubuntu with the full quality gates and on Windows with
  `python -m pytest -q`, across Python 3.11–3.13 (`.github/workflows/ci.yml`).
- The self-scan test scans this working tree, so repository changes — including documentation
  links from the root README and committed assets over the 1 MiB per-file budget — can fail it.
  Run the suite at your branch's final head.
