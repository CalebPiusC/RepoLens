"""Real CLI regressions for Stage 1B completeness and exit-code precedence."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    return subprocess.run(  # fixed argv, shell-free; paths and inputs come from tmp_path
        [sys.executable, "-m", "repolens", *args],
        text=True,
        capture_output=True,
        timeout=120,
        env=env,
        check=False,
    )


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_cli_json_and_terminal_report_omitted_eligible_links(tmp_path: Path) -> None:
    _write(tmp_path, "LICENSE", "MIT\n")
    _write(tmp_path, "README.md", "[ok](LICENSE)\n" * 500 + "[late](missing.md)\n")
    result = _run("scan", str(tmp_path), "--format", "json", "--min-severity", "critical")
    assert result.returncode == 3, result.stderr
    document = json.loads(result.stdout)
    assert document["schema_version"] == "1.1.0"
    assert document["result"]["status"] == "incomplete"
    assert document["result"]["exit_code"] == 3
    assert "analyzer_failed" in document["result"]["incomplete_reasons"]
    outcome = next(
        o
        for o in document["analyzer_outcomes"]
        if o["analyzer_name"] == "documentation-consistency"
    )
    assert outcome["status"] == "failed"
    assert outcome["coverage_truncated"] is False
    assert outcome["coverage_incomplete"] is False

    terminal = _run("scan", str(tmp_path), "--color", "never", "--min-severity", "critical")
    assert terminal.returncode == 3, terminal.stderr
    assert "incomplete" in terminal.stdout.lower()
    assert "500-link limit" in terminal.stdout


def test_cli_retains_broken_links_and_gives_findings_precedence(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "".join(f"[x](missing{i})\n" for i in range(11)))
    result = _run("scan", str(tmp_path), "--format", "json", "--min-severity", "low")
    assert result.returncode == 1, result.stderr
    document = json.loads(result.stdout)
    assert document["schema_version"] == "1.1.0"
    assert document["result"]["status"] == "findings_and_incomplete"
    assert document["result"]["exit_code"] == 1
    assert len([f for f in document["findings"] if f["rule_id"] == "RL-DOC-003"]) == 10


def test_cli_external_links_do_not_hide_later_broken_link(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "[web](https://example.com)\n" * 500 + "[x](missing.md)\n")
    result = _run("scan", str(tmp_path), "--format", "json", "--min-severity", "low")
    assert result.returncode == 1, result.stderr
    document = json.loads(result.stdout)
    assert any(f["rule_id"] == "RL-DOC-003" for f in document["findings"])
    outcome = next(
        o
        for o in document["analyzer_outcomes"]
        if o["analyzer_name"] == "documentation-consistency"
    )
    assert outcome["status"] == "completed"


def test_cli_inventory_and_test_sampling_gaps_cannot_be_clean(tmp_path: Path) -> None:
    _write(tmp_path, "pytest.ini", "[pytest]\n")
    for index in range(80):
        _write(tmp_path, f"inputs/{index:03}/requirements.txt", "")
    _write(tmp_path, "z/requirements.txt", "pytest==8.0.0\n")
    for index in range(21):
        _write(
            tmp_path, f"tests/test_{index:02}.py", "import pytest\n" if index == 20 else "# test\n"
        )
    result = _run("scan", str(tmp_path), "--format", "json", "--min-severity", "critical")
    assert result.returncode == 3, result.stderr
    document = json.loads(result.stdout)
    outcomes = {o["analyzer_name"]: o for o in document["analyzer_outcomes"]}
    assert outcomes["dependency-manifests"]["status"] == "failed"
    assert outcomes["testing-hygiene"]["status"] == "failed"
    assert outcomes["osv-dependency-check"]["status"] == "skipped"
    assert not any(f["rule_id"] == "RL-TEST-005" for f in document["findings"])
    assert document["result"]["is_complete"] is False


def test_cli_zero_and_usage_exit_codes(tmp_path: Path) -> None:
    _write(tmp_path, "LICENSE", "MIT\n")
    _write(tmp_path, "README.md", "[ok](LICENSE)\n" * 500)
    clean = _run("scan", str(tmp_path), "--format", "json", "--min-severity", "critical")
    assert clean.returncode == 0, clean.stderr
    document = json.loads(clean.stdout)
    assert document["result"]["status"] == "clean"
    assert document["schema_version"] == "1.1.0"
    usage = _run("scan", "--definitely-not-a-valid-option")
    assert usage.returncode == 2
