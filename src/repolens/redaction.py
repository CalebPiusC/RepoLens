"""Secret detection and redaction utilities for evidence snippets and error messages.

All evidence attached to findings or surfaced from subprocess errors passes through
this module so live credentials are never stored in reports or logs.
"""

from __future__ import annotations

import re

REDACTED_MARKER = "[REDACTED]"
TRUNCATION_SUFFIX = "... [truncated]"

# Ordered from most specific structural formats to generic key-value assignments.
# Patterns intentionally avoid nested ambiguous quantifiers to prevent ReDoS.
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----"
    r"[\s\S]{0,8192}?"
    r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----"
)
_PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[^\r\n]*")

_KNOWN_PREFIX_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # GitHub classic & fine-grained personal access, OAuth, app, and refresh tokens
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"), "[REDACTED_GITHUB_TOKEN]"),
    # AWS access key IDs
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # Google / Gemini API keys
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_GOOGLE_API_KEY]"),
    # Anthropic, OpenAI, and Stripe secret keys
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,255}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,255}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b"), "[REDACTED_STRIPE_KEY]"),
    # Slack tokens
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), "[REDACTED_SLACK_TOKEN]"),
    # PyPI and npm registry tokens
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{20,255}\b"), "[REDACTED_PYPI_TOKEN]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,255}\b"), "[REDACTED_NPM_TOKEN]"),
    # JSON Web Tokens (header.payload.signature)
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,512}\.eyJ[A-Za-z0-9_-]{10,1024}\.[A-Za-z0-9_-]{10,512}\b"
        ),
        "[REDACTED_JWT]",
    ),
)

# URLs containing userinfo credentials: scheme://user:password@host
_CREDENTIAL_URL_RE = re.compile(
    r"\b([a-zA-Z][a-zA-Z0-9+.-]{1,20}://[^/\s:@]{1,128}:)([^@\s/]{1,256})(@)"
)

# HTTP Authorization header values
_AUTH_HEADER_RE = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=-]{8,512})"
)

# Generic secret assignments in Python, JS/TS, YAML, TOML, JSON, or .env syntax:
# e.g. API_KEY = "secret123", "client_secret": "xyz...", password='...'
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)"
    r"([\"']?\b(?:[a-z0-9_]*?(?:password|passwd|pwd|secret|api_key|apikey|access_key|"
    r"private_key|auth_token|access_token|refresh_token|client_secret|database_url)\b"
    r"|\btoken\b)[\"']?\s*(?::=|:|=)\s*)"
    r"([\"'])([^\"'\r\n]{4,512})(\2)"
)

_UNQUOTED_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?im)"
    r"^(\s*(?:export\s+)?(?:[A-Z0-9_]*?(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|"
    r"ACCESS_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|CLIENT_SECRET|TOKEN))\s*=\s*)"
    r"([^\s#\"']{6,512})"
)

_SAFE_PLACEHOLDERS = frozenset(
    {
        "none",
        "null",
        "true",
        "false",
        "changeme",
        "your_api_key_here",
        "your-api-key-here",
        "example",
        "placeholder",
        "[redacted]",
        "redacted",
    }
)


def _replace_quoted_assignment(match: re.Match[str]) -> str:
    prefix, quote, value, closing_quote = match.groups()
    normalized = value.strip().lower()
    if normalized in _SAFE_PLACEHOLDERS or normalized.startswith(("${", "{{", "<")):
        return match.group(0)
    return f"{prefix}{quote}{REDACTED_MARKER}{closing_quote}"


def _replace_unquoted_assignment(match: re.Match[str]) -> str:
    prefix, value = match.groups()
    normalized = value.strip().lower()
    if normalized in _SAFE_PLACEHOLDERS or normalized.startswith(("${", "{{", "<")):
        return match.group(0)
    return f"{prefix}{REDACTED_MARKER}"


def redact_secrets(text: str, *, max_length: int = 500) -> str:
    """Redact credentials and sensitive tokens from ``text`` and enforce ``max_length``.

    Redaction runs on a bounded window slightly larger than ``max_length`` prior to
    truncation so secrets straddling the truncation boundary cannot leak partially.
    """
    if max_length < 32:
        raise ValueError("max_length must be at least 32 characters")
    if not text:
        return ""

    # Bound input size before regex evaluation while leaving headroom past max_length
    # so tokens crossing the boundary are still matched and redacted cleanly.
    window_limit = max(max_length + 1024, 4096)
    was_pre_sliced = len(text) > window_limit
    working = text[:window_limit]

    working = _PRIVATE_KEY_BLOCK_RE.sub("[REDACTED_PRIVATE_KEY]", working)
    working = _PRIVATE_KEY_HEADER_RE.sub("[REDACTED_PRIVATE_KEY]", working)

    for pattern, replacement in _KNOWN_PREFIX_PATTERNS:
        working = pattern.sub(replacement, working)

    working = _CREDENTIAL_URL_RE.sub(rf"\1{REDACTED_MARKER}\3", working)
    working = _AUTH_HEADER_RE.sub(rf"\1{REDACTED_MARKER}", working)
    working = _SECRET_ASSIGNMENT_RE.sub(_replace_quoted_assignment, working)
    working = _UNQUOTED_SECRET_ASSIGNMENT_RE.sub(_replace_unquoted_assignment, working)

    if len(working) <= max_length and not was_pre_sliced:
        return working

    budget = max_length - len(TRUNCATION_SUFFIX)
    if budget <= 0:
        return working[:max_length]
    return f"{working[:budget].rstrip()}{TRUNCATION_SUFFIX}"


def contains_secret(text: str) -> bool:
    """Return True if ``text`` matches any high-confidence secret pattern."""
    if not text:
        return False
    sample = text[:16_384]
    if _PRIVATE_KEY_HEADER_RE.search(sample):
        return True
    if any(pattern.search(sample) for pattern, _ in _KNOWN_PREFIX_PATTERNS):
        return True
    if _CREDENTIAL_URL_RE.search(sample) or _AUTH_HEADER_RE.search(sample):
        return True
    return redact_secrets(sample, max_length=max(len(sample), 500)) != sample
