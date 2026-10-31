#!/usr/bin/env bash
# Exercise the documented sh/bash virtualenv workflow, including the public main archive.
set -euo pipefail
unset PYTHONPATH PYTHONHOME VIRTUAL_ENV || true
export PYTHONUTF8=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1

work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/rl-activation.XXXXXX")
trap 'rm -rf "$work"' EXIT
venv="$work/repolens"
project="$work/project"
python tests/installation/lifecycle.py fixture --directory "$project"
expected=$(python -c "import runpy; print(runpy.run_path('src/repolens/_version.py')['__version__'])")
python --version
python -m venv "$venv"
# shellcheck disable=SC1091
. "$venv/bin/activate"
test "$(command -v python)" = "$venv/bin/python"
python -m pip install "$REPOLENS_MAIN_URL"
python -m pip check
test "$(command -v repolens)" = "$venv/bin/repolens"
main_version=$(python -c "import importlib.metadata as m; print(m.version('repolens'))")
test "$(repolens --version)" = "repolens $main_version"
(
  cd "$project"
  repolens scan . --color never
  python -m repolens scan . --format json > "$work/report.json"
)
python -m pip uninstall --yes repolens
test ! -e "$venv/bin/repolens"

# The immutable commit exercises the exact PR/branch build even before main is updated.
python -m pip install "$REPOLENS_SOURCE_URL"
python -m pip check
test "$(repolens --version)" = "repolens $expected"
test "$(python -m repolens --version)" = "repolens $expected"
python -m pip install --force-reinstall "$REPOLENS_SOURCE_URL"
test "$(repolens --version)" = "repolens $expected"
python -m pip uninstall --yes repolens
test ! -e "$venv/bin/repolens"
if python -m pip show repolens; then
  echo 'Package unexpectedly remains installed' >&2
  exit 1
fi
python -m pip check
deactivate
echo 'Linux shell activation, main and pinned source, scan, reinstall and uninstall passed.'
