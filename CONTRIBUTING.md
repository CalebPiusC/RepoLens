# Contributing

The contribution guide lives in [docs/contributing/README.md](docs/contributing/README.md):
development setup with `pip`, the exact quality gates CI runs (`ruff`, `mypy src tests`,
`pytest` with coverage), a runnable new-analyzer example, JSON schema-change rules, and the
pull-request process.

Quick start (Linux/macOS):

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests && mypy src tests && pytest
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
ruff check src tests
ruff format --check src tests
mypy src tests
python -m pytest
```

For vulnerabilities in RepoLens itself, do not open a public issue — see
[SECURITY.md](SECURITY.md).
