"""Safe repository file discovery, .gitignore matching, and read boundaries."""

from __future__ import annotations

import errno
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from repolens.config import HYGIENE_TRACKED_ARTIFACT_DIRS, ScanConfig
from repolens.exceptions import (
    DiscoveryAbortedError,
    DiscoveryError,
    OversizedFileAccessError,
    PathSecurityError,
    SensitiveFileAccessError,
)
from repolens.models import DetectedLanguage, DiscoverySummary

MAX_DIRECTORY_DEPTH = 64

_SAFE_ENV_TEMPLATES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        ".env.defaults",
        ".env.schema",
    }
)

_SENSITIVE_EXACT_NAMES: dict[str, str] = {
    ".env": "Environment variable file (.env)",
    ".pypirc": "PyPI publishing credentials (.pypirc)",
    ".netrc": "Network authentication credentials (.netrc)",
    ".git-credentials": "Git plaintext credentials (.git-credentials)",
    "id_rsa": "SSH RSA private key",
    "id_dsa": "SSH DSA private key",
    "id_ecdsa": "SSH ECDSA private key",
    "id_ed25519": "SSH Ed25519 private key",
    "credentials.json": "Service or OAuth credentials file (credentials.json)",
    "client_secret.json": "OAuth client secret file (client_secret.json)",
}

_SENSITIVE_EXTENSIONS: dict[str, str] = {
    ".pem": "PEM key or certificate bundle",
    ".key": "Private cryptographic key file",
    ".p12": "PKCS#12 archive / private key bundle",
    ".pfx": "PFX certificate / private key bundle",
    ".jks": "Java keystore file",
    ".keystore": "Cryptographic keystore file",
    ".kdbx": "KeePass password database",
}

_PYTHON_MANIFESTS: frozenset[str] = frozenset(
    {"pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "uv.lock", "poetry.lock"}
)


def classify_sensitive_file(rel_posix_path: str) -> str | None:
    """Return a sensitivity description if ``rel_posix_path`` matches a secret-bearing file.

    Safe placeholder templates such as ``.env.example`` are explicitly permitted.
    """
    posix = PurePosixPath(rel_posix_path)
    name = posix.name
    lower_name = name.lower()

    if lower_name in _SAFE_ENV_TEMPLATES:
        return None

    if lower_name in _SENSITIVE_EXACT_NAMES:
        return _SENSITIVE_EXACT_NAMES[lower_name]

    if lower_name.startswith(".env."):
        return f"Environment variable file ({name})"

    if rel_posix_path == ".streamlit/secrets.toml" or rel_posix_path.endswith(
        "/.streamlit/secrets.toml"
    ):
        return "Streamlit secrets file (.streamlit/secrets.toml)"

    if lower_name.startswith("service-account") and lower_name.endswith(".json"):
        return f"Cloud service account key ({name})"

    suffix = posix.suffix.lower()
    if suffix in _SENSITIVE_EXTENSIONS:
        return _SENSITIVE_EXTENSIONS[suffix]

    return None


@dataclass(frozen=True, slots=True)
class _IgnoreRule:
    regex: re.Pattern[str]
    negated: bool
    dir_only: bool
    anchored: bool


def _gitignore_glob_to_regex(pattern: str) -> str:
    """Translate a gitignore glob expression into a regular expression body."""
    parts: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 < n:
                parts.append(re.escape(pattern[i + 1]))
                i += 2
            else:
                parts.append(r"\\")
                i += 1
        elif ch == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                if i + 2 < n and pattern[i + 2] == "/":
                    parts.append("(?:.+/)?")
                    i += 3
                else:
                    parts.append(".*")
                    i += 2
            else:
                parts.append("[^/]*")
                i += 1
        elif ch == "?":
            parts.append("[^/]")
            i += 1
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end != -1:
                inner = pattern[i + 1 : end]
                if inner.startswith("!"):
                    inner = "^" + inner[1:]
                parts.append(f"[{inner}]")
                i = end + 1
            else:
                parts.append(r"\[")
                i += 1
        else:
            parts.append(re.escape(ch))
            i += 1
    return "".join(parts)


class GitIgnoreMatcher:
    """Lightweight, deterministic matcher for repository ``.gitignore`` rules."""

    def __init__(self, content: str = "") -> None:
        self._rules: list[_IgnoreRule] = []
        for raw_line in content.splitlines():
            rule = self._parse_line(raw_line)
            if rule is not None:
                self._rules.append(rule)

    @staticmethod
    def _parse_line(raw_line: str) -> _IgnoreRule | None:
        line = raw_line.rstrip("\r\n")
        if not line:
            return None
        # Trim unescaped trailing spaces
        while line.endswith(" ") and not line.endswith(r"\ "):
            line = line[:-1]
        if not line or line.startswith("#"):
            return None

        negated = False
        if line.startswith("!"):
            negated = True
            line = line[1:]
        elif line.startswith((r"\#", r"\!")):
            line = line[1:]

        dir_only = line.endswith("/")
        if dir_only:
            line = line.rstrip("/")
        if not line:
            return None

        anchored = "/" in line
        if line.startswith("/"):
            line = line.lstrip("/")
        if not line:
            return None

        body = _gitignore_glob_to_regex(line)
        regex_str = f"^{body}$" if anchored else f"^(?:.+/)?{body}$"
        return _IgnoreRule(
            regex=re.compile(regex_str),
            negated=negated,
            dir_only=dir_only,
            anchored=anchored,
        )

    def is_ignored(self, rel_posix_path: str, *, is_dir: bool = False) -> bool:
        """Return True if ``rel_posix_path`` (or any of its parent directories) is ignored."""
        normalized = rel_posix_path.strip("/")
        if not normalized:
            return False

        segments = normalized.split("/")
        # Check parent directories first: if a parent directory is ignored, descendants are too.
        for idx in range(1, len(segments)):
            parent = "/".join(segments[:idx])
            if self._matches_single(parent, is_dir=True):
                return True

        return self._matches_single(normalized, is_dir=is_dir)

    def _matches_single(self, path: str, *, is_dir: bool) -> bool:
        ignored = False
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.regex.match(path):
                ignored = not rule.negated
        return ignored


@dataclass(frozen=True, slots=True)
class DiscoveredFile:
    """Metadata for a single safely discovered file inside the repository root."""

    path: str
    size_bytes: int
    is_sensitive: bool = False
    sensitive_reason: str | None = None
    is_oversized: bool = False


class RepositoryContext:
    """Immutable-view snapshot of a discovered repository with safe read accessors."""

    def __init__(
        self,
        *,
        canonical_root: Path,
        repository_name: str,
        config: ScanConfig,
        files: tuple[DiscoveredFile, ...],
        present_artifact_dirs: tuple[str, ...],
        skipped_symlinks: tuple[str, ...],
        gitignore: GitIgnoreMatcher,
        has_gitignore: bool,
        summary: DiscoverySummary,
    ) -> None:
        self.canonical_root = canonical_root
        self.repository_name = repository_name
        self.config = config
        self.files = files
        self.files_by_path: dict[str, DiscoveredFile] = {f.path: f for f in files}
        self.present_artifact_dirs = present_artifact_dirs
        self.skipped_symlinks = skipped_symlinks
        self.gitignore = gitignore
        self.has_gitignore = has_gitignore
        self.summary = summary

    @property
    def detected_languages(self) -> list[DetectedLanguage]:
        """Languages detected during repository discovery."""
        return list(self.summary.detected_languages)

    def has_file(self, rel_posix_path: str) -> bool:
        """Return True if ``rel_posix_path`` exists in the discovered file set."""
        return rel_posix_path in self.files_by_path

    def read_text(self, rel_posix_path: str) -> str:
        """Safely read UTF-8 text from a discovered, non-sensitive, size-bounded file."""
        if (
            not rel_posix_path
            or "\x00" in rel_posix_path
            or "\\" in rel_posix_path
            or rel_posix_path.startswith("/")
            or ".." in PurePosixPath(rel_posix_path).parts
        ):
            raise PathSecurityError(f"Unsafe relative path requested: {rel_posix_path!r}")

        info = self.files_by_path.get(rel_posix_path)
        if info is None:
            raise DiscoveryError(f"File was not part of safe discovery: {rel_posix_path}")

        if info.is_sensitive:
            raise SensitiveFileAccessError(
                f"Refusing to read sensitive file contents: {rel_posix_path}"
            )

        if info.is_oversized:
            raise OversizedFileAccessError(
                f"Refusing to read oversized file ({info.size_bytes} bytes): {rel_posix_path}"
            )

        target = self.canonical_root.joinpath(*PurePosixPath(rel_posix_path).parts)
        if target.is_symlink():
            raise PathSecurityError(f"Refusing to read symbolic link: {rel_posix_path}")

        resolved = target.resolve(strict=True)
        if not resolved.is_relative_to(self.canonical_root):
            raise PathSecurityError(f"Path escaped repository root: {rel_posix_path}")

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PathSecurityError(
                    f"Symbolic link detected during open: {rel_posix_path}"
                ) from exc
            raise DiscoveryError(f"Unable to open {rel_posix_path}: {exc}") from exc

        try:
            with os.fdopen(fd, "rb") as handle:
                raw = handle.read(self.config.max_file_size_bytes + 1)
        except OSError as exc:
            raise DiscoveryError(f"Failed reading {rel_posix_path}: {exc}") from exc

        if len(raw) > self.config.max_file_size_bytes:
            raise OversizedFileAccessError(
                f"File grew beyond max_file_size_bytes during scan: {rel_posix_path}"
            )

        return raw.decode("utf-8", errors="replace")


def _detect_languages(files: list[DiscoveredFile]) -> list[DetectedLanguage]:
    has_python = False
    has_js = False
    has_ts = False

    for item in files:
        posix = PurePosixPath(item.path)
        name = posix.name
        suffix = posix.suffix.lower()

        if (
            suffix in {".py", ".pyi"}
            or name in _PYTHON_MANIFESTS
            or (name.startswith("requirements") and suffix in {".txt", ".in"})
        ):
            has_python = True
        if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
            has_js = True
        if suffix in {".ts", ".tsx", ".mts", ".cts"} or name == "tsconfig.json":
            has_ts = True
        if name == "package.json" and not has_ts:
            has_js = True

    detected: list[DetectedLanguage] = []
    if has_python:
        detected.append(DetectedLanguage.PYTHON)
    if has_js:
        detected.append(DetectedLanguage.JAVASCRIPT)
    if has_ts:
        detected.append(DetectedLanguage.TYPESCRIPT)
    return detected


def discover_repository(repo_path: Path, config: ScanConfig | None = None) -> RepositoryContext:
    """Walk ``repo_path`` safely without following symlinks and enforce resource limits."""
    active_config = config or ScanConfig()

    try:
        exists_or_link = repo_path.exists() or repo_path.is_symlink()
    except OSError as exc:
        raise DiscoveryError(f"Cannot inspect path {repo_path}: {exc}") from exc

    if not exists_or_link:
        raise DiscoveryError(f"Repository path does not exist: {repo_path}")

    if active_config.reject_symlink_root and repo_path.is_symlink():
        raise PathSecurityError(f"Repository root must not be a symbolic link: {repo_path}")

    try:
        canonical_root = repo_path.resolve(strict=True)
    except OSError as exc:
        raise DiscoveryError(f"Cannot resolve repository root {repo_path}: {exc}") from exc

    if not canonical_root.is_dir():
        raise DiscoveryError(f"Repository path is not a directory: {repo_path}")

    discovered_files: list[DiscoveredFile] = []
    present_artifact_dirs: list[str] = []
    skipped_symlinks: list[str] = []

    total_bytes_scanned = 0
    skipped_excluded_count = 0
    skipped_symlink_count = 0
    skipped_oversized_count = 0
    sensitive_files_detected = 0
    truncated_by_file_limit = False
    truncated_by_byte_limit = False
    unreadable_directory_count = 0
    unreadable_entry_count = 0
    skipped_by_depth_count = 0

    # Iterative DFS stack: (directory_path, relative_posix_prefix, depth)
    stack: list[tuple[Path, str, int]] = [(canonical_root, "", 0)]

    while stack:
        current_dir, rel_prefix, depth = stack.pop()
        try:
            with os.scandir(current_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            # The directory exists in the walk but its contents are invisible to us, so
            # anything inside it goes unchecked. Record it: a scan that could not look
            # everywhere must never be reported as clean.
            unreadable_directory_count += 1
            continue

        subdirs_to_push: list[tuple[Path, str, int]] = []

        for entry in entries:
            name = entry.name
            if not name or "\x00" in name or "/" in name or "\\" in name:
                continue

            rel_posix = f"{rel_prefix}/{name}" if rel_prefix else name

            try:
                if entry.is_symlink():
                    skipped_symlink_count += 1
                    skipped_symlinks.append(rel_posix)
                    continue

                entry_path = Path(entry.path)
                resolved_entry = entry_path.resolve()
                if not resolved_entry.is_relative_to(canonical_root):
                    raise DiscoveryAbortedError(f"Entry escaped canonical root: {rel_posix}")

                if entry.is_dir(follow_symlinks=False):
                    if name in active_config.excluded_dirs:
                        skipped_excluded_count += 1
                        if name in HYGIENE_TRACKED_ARTIFACT_DIRS:
                            present_artifact_dirs.append(rel_posix)
                        continue
                    if depth < MAX_DIRECTORY_DEPTH:
                        subdirs_to_push.append((entry_path, rel_posix, depth + 1))
                    else:
                        # Beyond the supported nesting depth the subtree is not walked at
                        # all. Record it: nested sources would otherwise go unchecked
                        # while the scan still looked complete.
                        skipped_by_depth_count += 1
                    continue

                if not entry.is_file(follow_symlinks=False):
                    continue

                stat_result = entry.stat(follow_symlinks=False)
            except PathSecurityError:
                raise
            except OSError:
                # A single unreadable/undecidable entry: skip it but keep it visible in
                # the summary so it cannot masquerade as a clean scan.
                unreadable_entry_count += 1
                continue

            if len(discovered_files) >= active_config.max_files:
                truncated_by_file_limit = True
                stack.clear()
                subdirs_to_push.clear()
                break

            size_bytes = stat_result.st_size
            sensitive_reason = classify_sensitive_file(rel_posix)
            is_sensitive = sensitive_reason is not None
            is_oversized = size_bytes > active_config.max_file_size_bytes

            if is_sensitive:
                sensitive_files_detected += 1

            if is_oversized:
                skipped_oversized_count += 1
            elif not is_sensitive:
                if total_bytes_scanned + size_bytes > active_config.max_total_bytes:
                    truncated_by_byte_limit = True
                    stack.clear()
                    subdirs_to_push.clear()
                    break
                total_bytes_scanned += size_bytes

            discovered_files.append(
                DiscoveredFile(
                    path=rel_posix,
                    size_bytes=size_bytes,
                    is_sensitive=is_sensitive,
                    sensitive_reason=sensitive_reason,
                    is_oversized=is_oversized,
                )
            )

        # Push in reverse order so alphabetical order is preserved when popping LIFO.
        for subdir in reversed(subdirs_to_push):
            stack.append(subdir)

    discovered_files.sort(key=lambda f: f.path)
    present_artifact_dirs.sort()
    skipped_symlinks.sort()

    detected_languages = _detect_languages(discovered_files)

    summary = DiscoverySummary(
        total_files_scanned=len(discovered_files),
        total_bytes_scanned=total_bytes_scanned,
        skipped_excluded_count=skipped_excluded_count,
        skipped_symlink_count=skipped_symlink_count,
        skipped_oversized_count=skipped_oversized_count,
        sensitive_files_detected=sensitive_files_detected,
        truncated_by_file_limit=truncated_by_file_limit,
        truncated_by_byte_limit=truncated_by_byte_limit,
        unreadable_directory_count=unreadable_directory_count,
        unreadable_entry_count=unreadable_entry_count,
        skipped_by_depth_count=skipped_by_depth_count,
        detected_languages=detected_languages,
    )

    temp_context = RepositoryContext(
        canonical_root=canonical_root,
        repository_name=canonical_root.name or "repository",
        config=active_config,
        files=tuple(discovered_files),
        present_artifact_dirs=tuple(present_artifact_dirs),
        skipped_symlinks=tuple(skipped_symlinks),
        gitignore=GitIgnoreMatcher(),
        has_gitignore=False,
        summary=summary,
    )

    gitignore_info = temp_context.files_by_path.get(".gitignore")
    has_gitignore = gitignore_info is not None
    gitignore_matcher = GitIgnoreMatcher()
    if (
        gitignore_info is not None
        and not gitignore_info.is_oversized
        and not gitignore_info.is_sensitive
    ):
        gitignore_matcher = GitIgnoreMatcher(temp_context.read_text(".gitignore"))

    return RepositoryContext(
        canonical_root=canonical_root,
        repository_name=canonical_root.name or "repository",
        config=active_config,
        files=tuple(discovered_files),
        present_artifact_dirs=tuple(present_artifact_dirs),
        skipped_symlinks=tuple(skipped_symlinks),
        gitignore=gitignore_matcher,
        has_gitignore=has_gitignore,
        summary=summary,
    )
