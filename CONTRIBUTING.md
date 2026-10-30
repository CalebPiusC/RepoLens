# Contributing

The contribution guide lives in [docs/contributing/README.md](docs/contributing/README.md):
development setup with `pip`, the exact quality gates CI runs (`ruff`, `mypy src tests`,
`pytest` with coverage), a runnable new-analyzer example, JSON schema-change rules, and the
pull-request process.

Quick start:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests && mypy src tests && pytest
```

For vulnerabilities in RepoLens itself, do not open a public issue — see
[SECURITY.md](SECURITY.md).
