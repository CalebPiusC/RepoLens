"""Security tests for secret redaction and hardened subprocess execution."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from repolens.exceptions import SubprocessExecutionError
from repolens.redaction import TRUNCATION_SUFFIX, contains_secret, redact_secrets
from repolens.subprocess_runner import build_sanitized_env, run_safe_command


@pytest.mark.parametrize(
    "raw_snippet",
    [
        "ghp_" + "9aBcDeFgHiJkLmNoPqRs" * 2,
        "github_pat_" + "1234567890abcdefghij_ABC",
        "AIza" + "SyDa1234567890abcdefghijklmnopqrstu",
        "AKIAIOSFODNN7EXAMPLE",
        "sk-proj-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4",
        "postgres://admin:SuperSecretPass99!@db.internal:5432/prod",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNA",
        'GEMINI_API_KEY = "my-ultra-secret-gemini-key-value"',
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_redact_secrets_scrubs_credential_formats(raw_snippet: str) -> None:
    assert contains_secret(raw_snippet) is True
    scrubbed = redact_secrets(raw_snippet)
    assert scrubbed != raw_snippet
    assert "REDACTED" in scrubbed
    assert "SuperSecretPass99" not in scrubbed
    assert "my-ultra-secret-gemini-key-value" not in scrubbed


def test_redact_secrets_preserves_safe_placeholders() -> None:
    safe = 'API_KEY = "${API_KEY}"\nPASSWORD = "changeme"\nnormal_count = 42'
    assert redact_secrets(safe) == safe


def test_redact_secrets_prevents_partial_leak_across_truncation_boundary() -> None:
    secret = "ghp_" + "Z" * 36
    prefix = "x" * 90 + " "
    # Secret starts at index 91 and crosses max_length=100
    payload = prefix + secret
    scrubbed = redact_secrets(payload, max_length=100)
    assert "ghp_" not in scrubbed
    assert "ZZZZ" not in scrubbed
    assert scrubbed.endswith(TRUNCATION_SUFFIX)
    assert len(scrubbed) <= 100


def test_sanitized_env_strips_ambient_host_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSecretHostKey000000000000000000000")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_HostTokenThatMustNeverLeak1234567890")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    monkeypatch.setenv("DATABASE_URL", "postgres://prod:secret@host/db")

    env = build_sanitized_env()
    assert "GEMINI_API_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "DATABASE_URL" not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0"

    # Verify a real child process cannot observe the host secrets either
    result = run_safe_command(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('GEMINI_API_KEY', 'ABSENT'))",
        ],
        cwd=Path.cwd(),
        timeout_seconds=5.0,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "ABSENT"


def test_subprocess_runner_enforces_timeout(tmp_path: Path) -> None:
    result = run_safe_command(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=tmp_path,
        timeout_seconds=0.3,
    )
    assert result.timed_out is True
    assert result.returncode is None


def test_subprocess_runner_caps_runaway_output(tmp_path: Path) -> None:
    result = run_safe_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('A' * 65536)"],
        cwd=tmp_path,
        timeout_seconds=5.0,
        max_output_bytes=4096,
    )
    assert result.returncode == 0
    assert result.output_truncated is True
    assert len(result.stdout.encode("utf-8")) == 4096


def test_subprocess_runner_rejects_shell_strings_and_unsafe_cwd(tmp_path: Path) -> None:
    with pytest.raises(SubprocessExecutionError, match="sequence"):
        run_safe_command("echo unsafe", cwd=tmp_path)

    with pytest.raises(SubprocessExecutionError):
        run_safe_command([], cwd=tmp_path)

    with pytest.raises(SubprocessExecutionError, match="not found"):
        run_safe_command(["definitely-nonexistent-repolens-binary-xyz"], cwd=tmp_path)

    link_dir = tmp_path / "symlink_cwd"
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir.symlink_to(real_dir)
    with pytest.raises(SubprocessExecutionError, match="working directory"):
        run_safe_command([sys.executable, "-c", "pass"], cwd=link_dir)
