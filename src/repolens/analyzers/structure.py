"""Deterministic repository structure, manifest, and secret-hygiene analyzer."""

from __future__ import annotations

import json
import tomllib
from pathlib import PurePosixPath

from repolens import __version__
from repolens.analyzers.base import Analyzer
from repolens.config import ScanConfig
from repolens.discovery import DiscoveredFile, RepositoryContext
from repolens.models import (
    Category,
    Confidence,
    DetectedLanguage,
    Finding,
    FindingLocation,
    FindingSource,
    Severity,
    SourceKind,
)

_SOURCE = FindingSource(
    kind=SourceKind.DETERMINISTIC,
    tool="repolens-structure",
    tool_version=__version__,
)

_LICENSE_NAMES: frozenset[str] = frozenset(
    {
        "license",
        "license.md",
        "license.txt",
        "license.rst",
        "licence",
        "licence.md",
        "licence.txt",
        "copying",
        "copying.md",
        "copying.txt",
    }
)

_README_NAMES: frozenset[str] = frozenset(
    {
        "readme",
        "readme.md",
        "readme.rst",
        "readme.txt",
        "readme.adoc",
    }
)

_JS_LOCKFILES: dict[str, str] = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "bun.lockb": "bun",
    "bun.lock": "bun",
}

_CRITICAL_KEY_EXTENSIONS: frozenset[str] = frozenset(
    {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx"}
)
_CRITICAL_KEY_NAMES: frozenset[str] = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})

_BINARY_BLOAT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".7z",
        ".rar",
        ".whl",
        ".egg",
        ".pyc",
        ".pyo",
        ".pyd",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".class",
        ".jar",
        ".sqlite",
        ".sqlite3",
        ".db",
    }
)


class StructureAnalyzer(Analyzer):
    """Checks repository layout, ignore rules, manifests, and committed artifact hygiene."""

    @property
    def name(self) -> str:
        return "repolens-structure"

    def analyze(self, context: RepositoryContext, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_license(context))
        findings.extend(self._check_readme(context))
        findings.extend(self._check_gitignore(context))
        findings.extend(self._check_sensitive_files(context))
        findings.extend(self._check_artifact_directories(context))
        findings.extend(self._check_manifests_and_lockfiles(context))
        findings.extend(self._check_binary_and_oversized_files(context, config))
        return findings

    def _check_license(self, context: RepositoryContext) -> list[Finding]:
        for item in context.files:
            if "/" not in item.path and item.path.lower() in _LICENSE_NAMES:
                return []

        return [
            Finding(
                rule_id="RL-STRUCT-001",
                category=Category.STRUCTURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Missing repository LICENSE file",
                evidence="No root LICENSE or COPYING file was found in the repository.",
                explanation=(
                    "Without an explicit license file, default copyright law applies and others "
                    "cannot legally use, modify, or redistribute the code."
                ),
                recommendation=(
                    "Add a standard SPDX license file (such as MIT, Apache-2.0, or GPL-3.0) "
                    "named LICENSE at the repository root."
                ),
                verification="Confirm a non-empty LICENSE file exists at the repository root.",
                source=_SOURCE,
            )
        ]

    def _check_readme(self, context: RepositoryContext) -> list[Finding]:
        root_readmes = [
            item
            for item in context.files
            if "/" not in item.path and item.path.lower() in _README_NAMES
        ]
        if not root_readmes:
            return [
                Finding(
                    rule_id="RL-STRUCT-002",
                    category=Category.DOCUMENTATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="Missing root README file",
                    evidence="No README.md, README.rst, or README.txt found at repository root.",
                    explanation=(
                        "A root README is the primary entry point explaining what the project "
                        "does, how to install it, and how to run tests."
                    ),
                    recommendation=(
                        "Create a README.md at the repository root documenting project purpose, "
                        "setup steps, and basic usage."
                    ),
                    verification="Verify README.md exists at the repository root and has content.",
                    source=_SOURCE,
                )
            ]

        primary = root_readmes[0]
        if not primary.is_oversized and not primary.is_sensitive:
            text = context.read_text(primary.path)
            if not text.strip():
                return [
                    Finding(
                        rule_id="RL-STRUCT-002",
                        category=Category.DOCUMENTATION,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title="Empty root README file",
                        location=FindingLocation(path=primary.path, start_line=1),
                        evidence=f"{primary.path} contains 0 non-whitespace characters.",
                        explanation=(
                            "An empty README leaves users and contributors without setup, usage, "
                            "or architecture context."
                        ),
                        recommendation=(
                            f"Populate {primary.path} with a concise project overview, "
                            "installation instructions, and usage examples."
                        ),
                        verification=f"Verify {primary.path} contains clear documentation.",
                        source=_SOURCE,
                    )
                ]
        return []

    def _check_gitignore(self, context: RepositoryContext) -> list[Finding]:
        if not context.has_gitignore:
            return [
                Finding(
                    rule_id="RL-STRUCT-003",
                    category=Category.STRUCTURE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="Missing .gitignore file",
                    evidence="No .gitignore file found at the repository root.",
                    explanation=(
                        "Without a .gitignore file, local virtual environments, dependencies, "
                        "build caches, and .env secrets can easily be committed by mistake."
                    ),
                    recommendation=(
                        "Add a root .gitignore tailored to your language ecosystem (covering "
                        ".env, virtual environments, node_modules, and build artifacts)."
                    ),
                    verification=(
                        "Run `git status --ignored` to verify generated files are ignored."
                    ),
                    source=_SOURCE,
                )
            ]

        findings: list[Finding] = []
        languages = set(context.detected_languages)

        if DetectedLanguage.PYTHON in languages:
            missing_py: list[str] = []
            if not (
                context.gitignore.is_ignored("__pycache__", is_dir=True)
                or context.gitignore.is_ignored("module.pyc", is_dir=False)
            ):
                missing_py.append("__pycache__/ or *.pyc")
            if not (
                context.gitignore.is_ignored(".venv", is_dir=True)
                or context.gitignore.is_ignored("venv", is_dir=True)
            ):
                missing_py.append(".venv/")
            if not context.gitignore.is_ignored(".env", is_dir=False):
                missing_py.append(".env")

            if missing_py:
                joined = ", ".join(missing_py)
                findings.append(
                    Finding(
                        rule_id="RL-STRUCT-004",
                        category=Category.STRUCTURE,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        title="Incomplete Python .gitignore coverage",
                        location=FindingLocation(path=".gitignore"),
                        evidence=f"Missing ignore patterns for: {joined}",
                        explanation=(
                            "Python projects generate bytecode caches and local virtual "
                            "environments that pollute commits if omitted from .gitignore."
                        ),
                        recommendation=f"Add patterns covering {joined} to .gitignore.",
                        verification="Check `git check-ignore .venv __pycache__ .env`.",
                        source=_SOURCE,
                    )
                )

        if languages & {DetectedLanguage.JAVASCRIPT, DetectedLanguage.TYPESCRIPT} and not (
            context.gitignore.is_ignored("node_modules", is_dir=True)
        ):
            findings.append(
                Finding(
                    rule_id="RL-STRUCT-005",
                    category=Category.STRUCTURE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="node_modules is not ignored in .gitignore",
                    location=FindingLocation(path=".gitignore"),
                    evidence=".gitignore does not match `node_modules/`.",
                    explanation=(
                        "Committing node_modules bloats repository history with thousands of "
                        "third-party files that should be installed from a lockfile."
                    ),
                    recommendation="Add `node_modules/` and `.env` to .gitignore.",
                    verification="Run `git check-ignore node_modules/` and confirm it matches.",
                    source=_SOURCE,
                )
            )

        return findings

    def _check_sensitive_files(self, context: RepositoryContext) -> list[Finding]:
        findings: list[Finding] = []
        for item in context.files:
            if not item.is_sensitive:
                continue
            if context.has_gitignore and context.gitignore.is_ignored(item.path, is_dir=False):
                continue

            posix = PurePosixPath(item.path)
            is_private_key = (
                posix.suffix.lower() in _CRITICAL_KEY_EXTENSIONS
                or posix.name.lower() in _CRITICAL_KEY_NAMES
            )
            severity = Severity.CRITICAL if is_private_key else Severity.HIGH
            reason = item.sensitive_reason or "Sensitive credential or key file"

            findings.append(
                Finding(
                    rule_id="RL-SEC-001",
                    category=Category.SECURITY,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    title=f"Unignored sensitive file in repository: {posix.name}",
                    location=FindingLocation(path=item.path),
                    evidence=f"Path `{item.path}` classified as: {reason} (contents not read).",
                    explanation=(
                        "Sensitive environment files and private keys left unignored in a "
                        "repository risk permanent credential exposure in Git history."
                    ),
                    recommendation=(
                        f"Add `{item.path}` (or its pattern) to .gitignore, remove it from Git "
                        "tracking with `git rm --cached`, and rotate any exposed credentials."
                    ),
                    verification=(
                        f"Verify `git check-ignore {item.path}` succeeds and `git ls-files "
                        f"{item.path}` returns empty output."
                    ),
                    source=_SOURCE,
                )
            )
        return findings

    def _check_artifact_directories(self, context: RepositoryContext) -> list[Finding]:
        findings: list[Finding] = []
        for dir_path in context.present_artifact_dirs:
            if context.has_gitignore and context.gitignore.is_ignored(dir_path, is_dir=True):
                continue
            findings.append(
                Finding(
                    rule_id="RL-STRUCT-006",
                    category=Category.STRUCTURE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Unignored generated or vendor directory: {dir_path}",
                    location=FindingLocation(path=dir_path),
                    evidence=f"Directory `{dir_path}` exists in workspace and is not git-ignored.",
                    explanation=(
                        "Vendor directories, virtual environments, and bytecode caches are "
                        "environment-specific artifacts that degrade repository portability."
                    ),
                    recommendation=(
                        f"Add `{PurePosixPath(dir_path).name}/` to .gitignore and untrack any "
                        f"committed files under `{dir_path}`."
                    ),
                    verification=f"Confirm `git check-ignore {dir_path}` reports the directory.",
                    source=_SOURCE,
                )
            )
        return findings

    def _check_manifests_and_lockfiles(self, context: RepositoryContext) -> list[Finding]:
        findings: list[Finding] = []
        non_ignored_files = [
            f
            for f in context.files
            if not (context.has_gitignore and context.gitignore.is_ignored(f.path, is_dir=False))
        ]

        has_py_sources = any(
            PurePosixPath(f.path).suffix.lower() == ".py" for f in non_ignored_files
        )
        has_py_manifest = any(
            PurePosixPath(f.path).name in {"pyproject.toml", "setup.py", "setup.cfg", "Pipfile"}
            or (
                PurePosixPath(f.path).name.startswith("requirements")
                and PurePosixPath(f.path).suffix.lower() in {".txt", ".in"}
            )
            for f in non_ignored_files
        )
        if has_py_sources and not has_py_manifest:
            findings.append(
                Finding(
                    rule_id="RL-STRUCT-007",
                    category=Category.STRUCTURE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="Python source files without a project or dependency manifest",
                    evidence="Found .py source files without pyproject.toml or requirements.txt.",
                    explanation=(
                        "Without a package or dependency manifest, installs and automated "
                        "dependency vulnerability checks cannot determine required packages."
                    ),
                    recommendation=(
                        "Add a `pyproject.toml` (PEP 621) or `requirements.txt` declaring "
                        "supported Python versions and dependencies."
                    ),
                    verification="Verify `pyproject.toml` or `requirements.txt` exists at root.",
                    source=_SOURCE,
                )
            )

        has_jsts_sources = any(
            PurePosixPath(f.path).suffix.lower()
            in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
            for f in non_ignored_files
        )
        has_package_json = any(
            PurePosixPath(f.path).name == "package.json" for f in non_ignored_files
        )
        if has_jsts_sources and not has_package_json:
            findings.append(
                Finding(
                    rule_id="RL-STRUCT-007",
                    category=Category.STRUCTURE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title="JavaScript/TypeScript source files without package.json",
                    evidence="Found JS/TS source files without a package.json manifest.",
                    explanation=(
                        "JavaScript and TypeScript projects rely on package.json to declare "
                        "runtime dependencies, scripts, and module resolution settings."
                    ),
                    recommendation="Initialize a `package.json` file and commit a lockfile.",
                    verification="Confirm a valid `package.json` exists in the project.",
                    source=_SOURCE,
                )
            )

        pyproject = context.files_by_path.get("pyproject.toml")
        if pyproject is not None and not pyproject.is_oversized and not pyproject.is_sensitive:
            findings.extend(self._validate_pyproject_toml(context, pyproject))

        pkg_json = context.files_by_path.get("package.json")
        if pkg_json is not None and not pkg_json.is_oversized and not pkg_json.is_sensitive:
            findings.extend(self._validate_package_json_and_lockfiles(context, pkg_json))

        return findings

    def _validate_pyproject_toml(
        self, context: RepositoryContext, item: DiscoveredFile
    ) -> list[Finding]:
        raw = context.read_text(item.path)
        try:
            tomllib.loads(raw)
        except tomllib.TOMLDecodeError as exc:
            lineno = getattr(exc, "lineno", None)
            return [
                Finding(
                    rule_id="RL-STRUCT-011",
                    category=Category.STRUCTURE,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="Malformed pyproject.toml manifest",
                    location=FindingLocation(
                        path=item.path,
                        start_line=lineno if isinstance(lineno, int) and lineno >= 1 else 1,
                    ),
                    evidence=str(exc),
                    explanation=(
                        "A syntax error in pyproject.toml breaks package installation, build "
                        "backends, and tool configuration."
                    ),
                    recommendation="Fix the TOML syntax error in pyproject.toml.",
                    verification=(
                        'Run `python3 -c "import tomllib, pathlib; '
                        "tomllib.loads(pathlib.Path('pyproject.toml').read_text())\"`."
                    ),
                    source=_SOURCE,
                )
            ]
        return []

    def _validate_package_json_and_lockfiles(
        self, context: RepositoryContext, item: DiscoveredFile
    ) -> list[Finding]:
        raw = context.read_text(item.path)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            return [
                Finding(
                    rule_id="RL-STRUCT-011",
                    category=Category.STRUCTURE,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title="Malformed package.json manifest",
                    location=FindingLocation(path=item.path, start_line=max(exc.lineno, 1)),
                    evidence=f"JSONDecodeError at line {exc.lineno}, column {exc.colno}: {exc.msg}",
                    explanation=(
                        "Invalid JSON in package.json prevents npm, pnpm, yarn, and Biome from "
                        "parsing project configuration and dependencies."
                    ),
                    recommendation="Correct the JSON syntax in package.json.",
                    verification=(
                        "Run `python3 -m json.tool package.json > /dev/null` to confirm valid JSON."
                    ),
                    source=_SOURCE,
                )
            ]

        if not isinstance(parsed, dict):
            return []

        findings: list[Finding] = []
        present_lockfiles = [lf for lf in _JS_LOCKFILES if context.has_file(lf)]
        managers = sorted({_JS_LOCKFILES[lf] for lf in present_lockfiles})

        deps = parsed.get("dependencies")
        dev_deps = parsed.get("devDependencies")
        has_declared_deps = (isinstance(deps, dict) and bool(deps)) or (
            isinstance(dev_deps, dict) and bool(dev_deps)
        )

        if has_declared_deps and not present_lockfiles:
            findings.append(
                Finding(
                    rule_id="RL-STRUCT-008",
                    category=Category.STRUCTURE,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    title="Missing JavaScript/TypeScript dependency lockfile",
                    location=FindingLocation(path="package.json"),
                    evidence="package.json declares dependencies, but no lockfile was found.",
                    explanation=(
                        "Without a committed lockfile, builds are non-reproducible and transitive "
                        "dependencies cannot be reliably audited for known vulnerabilities."
                    ),
                    recommendation=(
                        "Generate and commit a lockfile (package-lock.json, pnpm-lock.yaml, "
                        "or yarn.lock) matching your package manager."
                    ),
                    verification="Confirm the generated lockfile is tracked in version control.",
                    source=_SOURCE,
                )
            )
        elif len(managers) > 1:
            joined_locks = ", ".join(sorted(present_lockfiles))
            findings.append(
                Finding(
                    rule_id="RL-STRUCT-009",
                    category=Category.STRUCTURE,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    title="Multiple conflicting JavaScript/TypeScript lockfiles",
                    location=FindingLocation(path="package.json"),
                    evidence=f"Conflicting lockfiles at root: {joined_locks}",
                    explanation=(
                        "Maintaining lockfiles from multiple package managers leads to drifted "
                        "dependency trees between local machines and CI."
                    ),
                    recommendation=(
                        "Standardize on a single package manager and remove redundant lockfiles."
                    ),
                    verification="Confirm only one package manager's lockfile exists at the root.",
                    source=_SOURCE,
                )
            )

        return findings

    def _check_binary_and_oversized_files(
        self, context: RepositoryContext, config: ScanConfig
    ) -> list[Finding]:
        findings: list[Finding] = []
        for item in context.files:
            if item.is_sensitive:
                continue
            if context.has_gitignore and context.gitignore.is_ignored(item.path, is_dir=False):
                continue

            suffix = PurePosixPath(item.path).suffix.lower()
            is_binary_bloat = suffix in _BINARY_BLOAT_EXTENSIONS

            if not item.is_oversized and not is_binary_bloat:
                continue

            detail = (
                f"File size {item.size_bytes:,} bytes exceeds limit "
                f"({config.max_file_size_bytes:,} bytes)."
                if item.is_oversized
                else f"Committed binary/archive artifact ({suffix}) of {item.size_bytes:,} bytes."
            )
            findings.append(
                Finding(
                    rule_id="RL-STRUCT-010",
                    category=Category.STRUCTURE,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM if item.is_oversized else Confidence.HIGH,
                    title=f"Binary, archive, or oversized artifact in repository: {item.path}",
                    location=FindingLocation(path=item.path),
                    evidence=detail,
                    explanation=(
                        "Large files, compiled binaries, local databases, and archives bloat "
                        "clone times and cannot be effectively diffed or statically audited."
                    ),
                    recommendation=(
                        f"Remove `{item.path}` from source control, add its pattern to "
                        ".gitignore, and distribute build artifacts via releases or registries."
                    ),
                    verification=f"Confirm `{item.path}` is removed or ignored in Git.",
                    source=_SOURCE,
                )
            )

        return findings
