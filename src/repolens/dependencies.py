"""Static, offline parsing of Python and JavaScript/TypeScript dependency manifests.

This module never installs, resolves, or executes anything. It reads only files that
were already accepted by safe repository discovery and turns them into a normalized
inventory of declared dependencies, locked package versions, and parse problems.

Supported Python inputs: ``pyproject.toml`` (PEP 621 and Poetry), ``Pipfile``,
``setup.cfg``, ``requirements*.txt`` / ``requirements*.in``, ``poetry.lock``,
``uv.lock``, ``pdm.lock``, and ``Pipfile.lock``.

Supported JavaScript/TypeScript inputs: ``package.json``, ``package-lock.json``,
``npm-shrinkwrap.json``, ``yarn.lock`` (classic and Berry), and a best-effort
``pnpm-lock.yaml`` reader. ``bun.lock``/``bun.lockb`` are detected but not parsed.
"""

from __future__ import annotations

import configparser
import json
import re
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, cast

from packaging.requirements import InvalidRequirement, Requirement

from repolens.discovery import RepositoryContext
from repolens.exceptions import DiscoveryError, OversizedFileAccessError, SensitiveFileAccessError

_MAX_PARSED_FILES = 80
_MAX_LOCK_TREE_DEPTH = 12

_REQUIREMENTS_NAME_RE = re.compile(r"^requirements[\w.-]*\.(?:txt|in)$", re.IGNORECASE)
_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,213}$")
_NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]{0,127}/)?[a-z0-9][a-z0-9._~-]{0,127}$")
_SAFE_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+!_-]{0,63}$")
_REQUIREMENTS_OPTION_PREFIXES = (
    "-r",
    "-c",
    "-e",
    "-i",
    "-f",
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "--trusted-host",
    "--requirement",
    "--constraint",
    "--editable",
    "--hash",
)
_PNPM_KEY_RE = re.compile(r"^(.+?):(?:\s|$)")
_PNPM_SECTION_RE = re.compile(r"^(?:packages|snapshots)\s*:\s*(.*)$")

_PYPROJECT_LOCKFILES = frozenset({"poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"})
_NPM_LOCKFILES = frozenset(
    {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
)
_UNSUPPORTED_NPM_LOCKFILES = frozenset({"bun.lock", "bun.lockb"})
_PY_MANIFEST_NAMES = frozenset({"pyproject.toml", "Pipfile", "setup.cfg"})

PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")


class Ecosystem(StrEnum):
    """Dependency ecosystems understood by RepoLens and OSV.dev."""

    PYPI = "PyPI"
    NPM = "npm"


class DependencyProblemKind(StrEnum):
    """Classification of a dependency parsing problem."""

    MALFORMED_MANIFEST = "malformed_manifest"
    MALFORMED_LOCKFILE = "malformed_lockfile"
    INVALID_REQUIREMENT = "invalid_requirement"
    UNSUPPORTED_LOCKFILE = "unsupported_lockfile"


@dataclass(frozen=True, slots=True)
class DeclaredDependency:
    """A dependency declared by a project manifest, with its raw version constraint."""

    ecosystem: Ecosystem
    name: str
    key: str
    specifier: str
    source_path: str
    dev: bool = False

    @property
    def exact_version(self) -> str | None:
        """Return the pinned version when the constraint is an exact ``==``/bare pin."""
        specifier = self.specifier.strip()
        if not specifier or specifier == "*":
            return None
        candidate: str | None = None
        if specifier.startswith("=="):
            candidate = specifier[2:].strip()
        elif specifier[0].isdigit() and specifier.replace(".", "").replace("-", "").isalnum():
            candidate = specifier
        if candidate is None or "*" in candidate or "," in candidate:
            return None
        return candidate if _SAFE_VERSION_RE.match(candidate) else None


@dataclass(frozen=True, slots=True)
class LockedPackage:
    """A concrete package version recorded by a lockfile or pinned requirement."""

    ecosystem: Ecosystem
    name: str
    version: str
    source_path: str

    @property
    def key(self) -> str:
        """Normalized comparison key for this package."""
        if self.ecosystem is Ecosystem.PYPI:
            return normalize_pypi_name(self.name)
        return normalize_npm_name(self.name)


@dataclass(frozen=True, slots=True)
class DependencyProblem:
    """A deterministic problem discovered while parsing dependency metadata."""

    kind: DependencyProblemKind
    path: str
    message: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class LockfileSummary:
    """Metadata about a parsed lockfile and how much RepoLens could verify from it."""

    path: str
    ecosystem: Ecosystem
    complete: bool
    package_count: int


@dataclass(frozen=True, slots=True)
class DependencyInventoryGap:
    """Eligible dependency data that could not be inventoried completely."""

    path: str
    ecosystem: Ecosystem
    reason: str
    affects_declarations: bool
    affects_lockfiles: bool


@dataclass(frozen=True, slots=True)
class DependencyInventory:
    """Normalized, offline view of every dependency manifest and lockfile in a repository."""

    declared: tuple[DeclaredDependency, ...] = ()
    locked: tuple[LockedPackage, ...] = ()
    problems: tuple[DependencyProblem, ...] = ()
    lockfiles: tuple[LockfileSummary, ...] = ()
    python_manifest_paths: tuple[str, ...] = ()
    npm_manifest_paths: tuple[str, ...] = ()
    gaps: tuple[DependencyInventoryGap, ...] = ()

    def declarations_complete(self, ecosystem: Ecosystem) -> bool:
        """Whether absence of a declaration can be established for this ecosystem."""
        return not any(gap.ecosystem is ecosystem and gap.affects_declarations for gap in self.gaps)

    def lockfiles_complete(self, ecosystem: Ecosystem, directory: str | None = None) -> bool:
        """Whether an omitted input could contain relevant locked packages."""
        return not any(
            gap.ecosystem is ecosystem
            and gap.affects_lockfiles
            and (directory is None or _parent_dir(gap.path) == directory)
            for gap in self.gaps
        )

    def gap_message(self) -> str | None:
        """Summarize actual omissions without embedding untrusted file contents."""
        if not self.gaps:
            return None
        counts: dict[str, int] = {}
        for gap in self.gaps:
            counts[gap.reason] = counts.get(gap.reason, 0) + 1
        details = "; ".join(f"{count} {reason}" for reason, count in sorted(counts.items()))
        return f"Dependency inventory incomplete: {details}."

    @property
    def has_python_manifests(self) -> bool:
        return bool(self.python_manifest_paths)

    @property
    def has_npm_manifests(self) -> bool:
        return bool(self.npm_manifest_paths)

    def declared_for(self, ecosystem: Ecosystem) -> tuple[DeclaredDependency, ...]:
        return tuple(item for item in self.declared if item.ecosystem == ecosystem)

    def lockfiles_for_dir(
        self, ecosystem: Ecosystem, directory: str
    ) -> tuple[LockfileSummary, ...]:
        return tuple(
            lockfile
            for lockfile in self.lockfiles
            if lockfile.ecosystem == ecosystem and _parent_dir(lockfile.path) == directory
        )

    def locked_names_for_dir(self, ecosystem: Ecosystem, directory: str) -> set[str]:
        sources = {
            lockfile.path
            for lockfile in self.lockfiles_for_dir(ecosystem, directory)
            if lockfile.complete
        }
        return {
            item.key
            for item in self.locked
            if item.ecosystem == ecosystem and item.source_path in sources
        }

    def has_python_lockfile(self) -> bool:
        """True when a Python lockfile (or fully pinned requirements) is present."""
        return any(
            lockfile.ecosystem == Ecosystem.PYPI and lockfile.complete
            for lockfile in self.lockfiles
        )

    def unique_packages(self) -> tuple[tuple[str, str, Ecosystem], ...]:
        """Return unique ``(name, version, ecosystem)`` triples for vulnerability queries."""
        seen: dict[tuple[str, str, Ecosystem], str] = {}
        for item in self.locked:
            if item.ecosystem not in (Ecosystem.PYPI, Ecosystem.NPM):
                continue
            if not _SAFE_VERSION_RE.match(item.version):
                continue
            if not item.name or len(item.name) > 214:
                continue
            seen.setdefault((item.key, item.version, item.ecosystem), item.name)
        triples = [(name, version, ecosystem) for (_, version, ecosystem), name in seen.items()]
        return tuple(
            sorted(triples, key=lambda entry: (entry[2].value, entry[0].lower(), entry[1]))
        )


def normalize_pypi_name(name: str) -> str:
    """Normalize a Python distribution name per PEP 503."""
    return PEP503_NORMALIZE_RE.sub("-", name.strip()).lower()


def normalize_npm_name(name: str) -> str:
    """Normalize an npm package name for comparison."""
    return name.strip().lower()


def _parent_dir(path: str) -> str:
    parent = PurePosixPath(path).parent
    return "" if parent == PurePosixPath(".") else parent.as_posix()


def _problem(
    kind: DependencyProblemKind, path: str, message: str, line: int | None = None
) -> DependencyProblem:
    return DependencyProblem(kind=kind, path=path, message=message[:1000], line=line)


def _declared(
    ecosystem: Ecosystem,
    name: str,
    specifier: str,
    path: str,
    *,
    dev: bool = False,
) -> DeclaredDependency | None:
    cleaned_name = name.strip()
    if not cleaned_name or len(cleaned_name) > 214:
        return None
    if ecosystem is Ecosystem.PYPI and not _PACKAGE_NAME_RE.match(cleaned_name):
        return None
    if ecosystem is Ecosystem.NPM and not _NPM_NAME_RE.match(normalize_npm_name(cleaned_name)):
        return None
    key = (
        normalize_pypi_name(cleaned_name)
        if ecosystem is Ecosystem.PYPI
        else (normalize_npm_name(cleaned_name))
    )
    return DeclaredDependency(
        ecosystem=ecosystem,
        name=cleaned_name,
        key=key,
        specifier=specifier.strip()[:200],
        source_path=path,
        dev=dev,
    )


# --------------------------------------------------------------------------------------
# Python manifests
# --------------------------------------------------------------------------------------


def _parse_pep508_entries(
    entries: object, path: str, *, dev: bool = False
) -> tuple[list[DeclaredDependency], list[DependencyProblem]]:
    declared: list[DeclaredDependency] = []
    problems: list[DependencyProblem] = []
    if not isinstance(entries, list):
        return declared, problems
    for entry in entries:
        if not isinstance(entry, str):
            continue
        try:
            requirement = Requirement(entry)
        except InvalidRequirement as exc:
            problems.append(
                _problem(
                    DependencyProblemKind.INVALID_REQUIREMENT,
                    path,
                    f"Invalid dependency specifier `{entry[:120]}`: {exc}",
                )
            )
            continue
        item = _declared(
            Ecosystem.PYPI, requirement.name, str(requirement.specifier), path, dev=dev
        )
        if item is not None:
            declared.append(item)
    return declared, problems


def _parse_pyproject(
    path: str, text: str
) -> tuple[list[DeclaredDependency], list[DependencyProblem]]:
    declared: list[DeclaredDependency] = []
    problems: list[DependencyProblem] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        problems.append(
            _problem(
                DependencyProblemKind.MALFORMED_MANIFEST,
                path,
                "pyproject.toml is not valid TOML.",
            )
        )
        return declared, problems

    project = data.get("project")
    if isinstance(project, dict):
        project_map = cast("dict[str, Any]", project)
        entries, entry_problems = _parse_pep508_entries(project_map.get("dependencies"), path)
        declared.extend(entries)
        problems.extend(entry_problems)
        optional = project_map.get("optional-dependencies")
        if isinstance(optional, dict):
            for group_entries in cast("dict[str, Any]", optional).values():
                entries, entry_problems = _parse_pep508_entries(group_entries, path, dev=True)
                declared.extend(entries)
                problems.extend(entry_problems)

    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group_entries in cast("dict[str, Any]", groups).values():
            entries, entry_problems = _parse_pep508_entries(group_entries, path, dev=True)
            declared.extend(entries)
            problems.extend(entry_problems)

    tool = data.get("tool")
    if isinstance(tool, dict):
        declared.extend(_parse_poetry_manifests(cast("dict[str, Any]", tool), path))

    return declared, problems


def _parse_poetry_manifests(tool: dict[str, Any], path: str) -> list[DeclaredDependency]:
    poetry = tool.get("poetry")
    if not isinstance(poetry, dict):
        return []

    poetry_map = cast("dict[str, Any]", poetry)
    declared = _parse_poetry_dependency_table(poetry_map.get("dependencies"), path, dev=False)

    group = poetry_map.get("group")
    if isinstance(group, dict):
        for group_config in cast("dict[str, Any]", group).values():
            if isinstance(group_config, dict):
                group_map = cast("dict[str, Any]", group_config)
                declared.extend(
                    _parse_poetry_dependency_table(group_map.get("dependencies"), path, dev=True)
                )

    dev_dependencies = poetry_map.get("dev-dependencies")
    declared.extend(_parse_poetry_dependency_table(dev_dependencies, path, dev=True))
    return declared


def _parse_poetry_dependency_table(
    table: object, path: str, *, dev: bool
) -> list[DeclaredDependency]:
    if not isinstance(table, dict):
        return []
    declared: list[DeclaredDependency] = []
    for raw_name, raw_spec in cast("dict[str, Any]", table).items():
        if not isinstance(raw_name, str) or raw_name.lower() == "python":
            continue
        specifier = ""
        if isinstance(raw_spec, str):
            specifier = raw_spec
        elif isinstance(raw_spec, dict):
            spec_map = cast("dict[str, Any]", raw_spec)
            if any(key in spec_map for key in ("path", "git", "url", "file")):
                continue
            version = spec_map.get("version")
            specifier = version if isinstance(version, str) else ""
        else:
            continue
        item = _declared(Ecosystem.PYPI, raw_name, specifier, path, dev=dev)
        if item is not None:
            declared.append(item)
    return declared


def _parse_pipfile(
    path: str, text: str
) -> tuple[list[DeclaredDependency], list[DependencyProblem]]:
    declared: list[DeclaredDependency] = []
    problems: list[DependencyProblem] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        problems.append(
            _problem(DependencyProblemKind.MALFORMED_MANIFEST, path, "Pipfile is not valid TOML.")
        )
        return declared, problems

    for section, dev in (("packages", False), ("dev-packages", True)):
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, spec in cast("dict[str, Any]", table).items():
            specifier = spec if isinstance(spec, str) else ""
            item = _declared(Ecosystem.PYPI, name, specifier, path, dev=dev)
            if item is not None:
                declared.append(item)
    return declared, []


def _parse_setup_cfg(
    path: str, text: str
) -> tuple[list[DeclaredDependency], list[DependencyProblem]]:
    declared: list[DeclaredDependency] = []
    problems: list[DependencyProblem] = []
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text, source=path)
    except configparser.Error as exc:
        problems.append(
            _problem(
                DependencyProblemKind.MALFORMED_MANIFEST,
                path,
                f"setup.cfg could not be parsed: {exc.message if hasattr(exc, 'message') else exc}",
            )
        )
        return declared, problems

    raw_requirements: list[str] = []
    if parser.has_option("options", "install_requires"):
        raw_requirements.extend(parser.get("options", "install_requires").splitlines())
    if parser.has_section("options.extras_require"):
        for _, value in parser.items("options.extras_require"):
            raw_requirements.extend(value.splitlines())

    cleaned = [line.strip() for line in raw_requirements if line.strip()]
    entries, entry_problems = _parse_pep508_entries(cleaned, path, dev=True)
    declared.extend(entries)
    problems.extend(entry_problems)
    return declared, problems


def _parse_requirements_file(
    path: str, text: str
) -> tuple[list[DeclaredDependency], list[LockedPackage], list[DependencyProblem]]:
    declared: list[DeclaredDependency] = []
    locked: list[LockedPackage] = []
    problems: list[DependencyProblem] = []

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            line = line[:-1].strip()
            if not line:
                continue
        lowered = line.lower()
        if lowered.startswith(_REQUIREMENTS_OPTION_PREFIXES):
            continue
        if "://" in line or line.startswith((".", "/", "git+", "hg+", "svn+", "bzr+")):
            # Local paths and VCS/URL requirements are not registry packages.
            continue

        candidate = line.split(" #", 1)[0].strip()
        try:
            requirement = Requirement(candidate)
        except InvalidRequirement as exc:
            problems.append(
                _problem(
                    DependencyProblemKind.INVALID_REQUIREMENT,
                    path,
                    f"Invalid requirement on line {number}: `{candidate[:120]}` ({exc})",
                    line=number,
                )
            )
            continue

        item = _declared(Ecosystem.PYPI, requirement.name, str(requirement.specifier), path)
        if item is None:
            continue
        declared.append(item)
        exact = item.exact_version
        if exact is not None:
            locked.append(LockedPackage(Ecosystem.PYPI, item.name, exact, path))

    return declared, locked, problems


# --------------------------------------------------------------------------------------
# Python lockfiles
# --------------------------------------------------------------------------------------


def _parse_toml_lockfile(
    path: str, text: str
) -> tuple[list[LockedPackage], list[DependencyProblem], bool]:
    problems: list[DependencyProblem] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return (
            [],
            [
                _problem(
                    DependencyProblemKind.MALFORMED_LOCKFILE,
                    path,
                    f"Lockfile is not valid TOML: {exc}",
                )
            ],
            False,
        )

    packages = data.get("package")
    if not isinstance(packages, list):
        return [], problems, False

    locked: list[LockedPackage] = []
    for raw in packages:
        if not isinstance(raw, dict):
            continue
        entry = cast("dict[str, Any]", raw)
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if not _SAFE_VERSION_RE.match(version) or len(name) > 214:
            continue
        locked.append(LockedPackage(Ecosystem.PYPI, name, version, path))
    return locked, problems, True


def _parse_pipfile_lock(
    path: str, text: str
) -> tuple[list[LockedPackage], list[DependencyProblem], bool]:
    try:
        data: object = json.loads(text)
    except json.JSONDecodeError as exc:
        return (
            [],
            [
                _problem(
                    DependencyProblemKind.MALFORMED_LOCKFILE,
                    path,
                    f"Pipfile.lock is not valid JSON: {exc.msg} (line {exc.lineno})",
                    line=max(exc.lineno, 1),
                )
            ],
            False,
        )
    except RecursionError:
        return (
            [],
            [
                _problem(
                    DependencyProblemKind.MALFORMED_LOCKFILE,
                    path,
                    "Pipfile.lock is too deeply nested to parse safely.",
                )
            ],
            False,
        )

    if not isinstance(data, dict):
        return [], [], False

    locked: list[LockedPackage] = []
    for section in ("default", "develop"):
        table = cast("dict[str, Any]", data).get(section)
        if not isinstance(table, dict):
            continue
        for name, raw in cast("dict[str, Any]", table).items():
            if not isinstance(name, str) or not isinstance(raw, dict):
                continue
            version = cast("dict[str, Any]", raw).get("version")
            if not isinstance(version, str):
                continue
            cleaned = version[2:] if version.startswith("==") else version
            if not _SAFE_VERSION_RE.match(cleaned) or len(name) > 214:
                continue
            locked.append(LockedPackage(Ecosystem.PYPI, name, cleaned, path))
    return locked, [], True


# --------------------------------------------------------------------------------------
# npm manifests and lockfiles
# --------------------------------------------------------------------------------------


def _parse_package_json(
    path: str, text: str
) -> tuple[list[DeclaredDependency], list[DependencyProblem]]:
    declared: list[DeclaredDependency] = []
    data = _safe_json_loads(text)
    if not isinstance(data, dict):
        return declared, [
            _problem(
                DependencyProblemKind.MALFORMED_MANIFEST,
                path,
                "package.json is not a valid JSON object.",
            )
        ]

    data_map = cast("dict[str, Any]", data)
    sections = (
        ("dependencies", False),
        ("devDependencies", True),
        ("optionalDependencies", False),
        ("peerDependencies", True),
    )
    for section, dev in sections:
        table = data_map.get(section)
        if not isinstance(table, dict):
            continue
        for name, spec in cast("dict[str, Any]", table).items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            lowered = spec.strip().lower()
            local_prefixes = (
                "file:",
                "link:",
                "workspace:",
                "git+",
                "git:",
                "http:",
                "https:",
                "github:",
                "portal:",
                "patch:",
            )
            if lowered.startswith(local_prefixes) or "//" in lowered:
                continue
            item = _declared(Ecosystem.NPM, name, spec, path, dev=dev)
            if item is not None:
                declared.append(item)
    return declared, []


def _npm_package_name(package_path: str) -> str | None:
    marker = "node_modules/"
    index = package_path.rfind(marker)
    if index < 0:
        return None
    name = package_path[index + len(marker) :].strip("/")
    if not name or not _NPM_NAME_RE.match(name.lower()):
        return None
    return name


def _parse_package_lock(
    path: str, text: str, *, ecosystem: Ecosystem = Ecosystem.NPM
) -> tuple[list[LockedPackage], list[DependencyProblem], bool, bool]:
    try:
        data: object = json.loads(text)
    except json.JSONDecodeError as exc:
        return (
            [],
            [
                _problem(
                    DependencyProblemKind.MALFORMED_LOCKFILE,
                    path,
                    f"`{PurePosixPath(path).name}` is not valid JSON: "
                    f"{exc.msg} (line {exc.lineno})",
                    line=max(exc.lineno, 1),
                )
            ],
            False,
            False,
        )
    except (RecursionError, ValueError):
        return (
            [],
            [
                _problem(
                    DependencyProblemKind.MALFORMED_LOCKFILE,
                    path,
                    f"`{PurePosixPath(path).name}` could not be parsed safely.",
                )
            ],
            False,
            False,
        )
    if not isinstance(data, dict):
        return (
            [],
            [
                _problem(
                    DependencyProblemKind.MALFORMED_LOCKFILE,
                    path,
                    f"`{PurePosixPath(path).name}` must contain a JSON object.",
                )
            ],
            False,
            False,
        )

    data_map = cast("dict[str, Any]", data)
    locked: list[LockedPackage] = []

    packages = data_map.get("packages")
    if isinstance(packages, dict):
        for key, entry in cast("dict[str, Any]", packages).items():
            if not isinstance(key, str) or not isinstance(entry, dict):
                continue
            name = _npm_package_name(key)
            if name is None:
                continue
            version = cast("dict[str, Any]", entry).get("version")
            if not isinstance(version, str) or not _SAFE_VERSION_RE.match(version):
                continue
            locked.append(LockedPackage(ecosystem, name, version, path))
        return locked, [], True, False

    dependencies = data_map.get("dependencies")
    if isinstance(dependencies, dict):
        omitted = _walk_npm_v1_dependencies(dependencies, path, locked, ecosystem, depth=0)
        return locked, [], not omitted, omitted

    return locked, [], False, False


def _walk_npm_v1_dependencies(
    table: dict[str, Any],
    path: str,
    locked: list[LockedPackage],
    ecosystem: Ecosystem,
    *,
    depth: int,
) -> bool:
    """Collect supported entries and report actual package omissions beyond the depth cap."""
    if depth > _MAX_LOCK_TREE_DEPTH:
        return _contains_npm_v1_package(table)
    omitted = False
    for name, raw in table.items():
        if not isinstance(name, str) or not isinstance(raw, dict):
            continue
        entry = cast("dict[str, Any]", raw)
        version = entry.get("version")
        if isinstance(version, str) and _SAFE_VERSION_RE.match(version) and len(name) <= 214:
            locked.append(LockedPackage(ecosystem, name, version, path))
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            omitted |= _walk_npm_v1_dependencies(nested, path, locked, ecosystem, depth=depth + 1)
    return omitted


def _contains_npm_v1_package(table: dict[str, Any]) -> bool:
    """Look past the limit without recursive traversal or collecting additional packages."""
    pending = [table]
    while pending:
        for name, raw in pending.pop().items():
            if not isinstance(name, str) or not isinstance(raw, dict):
                continue
            entry = cast("dict[str, Any]", raw)
            version = entry.get("version")
            if (
                name
                and len(name) <= 214
                and isinstance(version, str)
                and _SAFE_VERSION_RE.match(version)
            ):
                return True
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                pending.append(nested)
    return False


def _split_npm_selector(selector: str) -> tuple[str, str] | None:
    cleaned = selector.strip().strip('"').strip()
    if not cleaned:
        return None
    if cleaned.startswith("@"):
        separator = cleaned.find("@", 1)
        if separator <= 1:
            return None
        name, constraint = cleaned[:separator], cleaned[separator + 1 :]
    else:
        separator = cleaned.find("@")
        if separator <= 0:
            return None
        name, constraint = cleaned[:separator], cleaned[separator + 1 :]
    name = name.strip()
    if not _NPM_NAME_RE.match(name.lower()):
        return None
    return name, constraint.strip()


def _parse_yarn_lock(
    path: str, text: str
) -> tuple[list[LockedPackage], list[DependencyProblem], bool]:
    locked: list[LockedPackage] = []
    current_names: list[str] = []
    in_header = False

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if not raw_line[0].isspace():
            current_names = []
            in_header = raw_line.rstrip().endswith(":")
            if not in_header:
                continue
            header = raw_line.rstrip()[:-1]
            for selector in header.split(","):
                parsed = _split_npm_selector(selector)
                if parsed is not None:
                    current_names.append(parsed[0])
            continue

        if not in_header or not current_names:
            continue
        stripped = raw_line.strip()
        version: str | None = None
        if stripped.startswith("version:"):
            version = stripped.split(":", 1)[1].strip().strip('"')
        elif stripped.startswith("version "):
            version = stripped.split(None, 1)[1].strip().strip('"')
        if version is None:
            continue
        if not _SAFE_VERSION_RE.match(version):
            current_names = []
            continue
        for name in current_names:
            locked.append(LockedPackage(Ecosystem.NPM, name, version, path))
        current_names = []

    return locked, [], True


def _pnpm_coordinate(raw_key: str) -> tuple[str, str] | None:
    """Interpret common pnpm v5/v6/v9 package and snapshot keys without a YAML parser."""
    key = raw_key.strip()
    if key.startswith("'") and key.endswith("'"):
        key = key[1:-1].replace("''", "'")
    elif key.startswith('"') and key.endswith('"'):
        try:
            key = json.loads(key)
        except (json.JSONDecodeError, RecursionError):
            return None
    key = key.lstrip("/")
    if "(" in key:
        key, suffix = key.split("(", 1)
        depth = 1
        for char in suffix:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif depth == 0:
                return None
            if depth < 0:
                return None
        if depth:
            return None
    parsed = _split_npm_selector(key)
    if parsed is None and "/" in key:
        # v5 uses /name/version, including /@scope/name/version.
        name, version = key.rsplit("/", 1)
    elif parsed is not None:
        name, version = parsed
    else:
        return None
    # Older pnpm releases encode peer qualifiers as _peer@version.
    if "_" in version and "@" in version.split("_", 1)[1]:
        version = version.split("_", 1)[0]
    if not _NPM_NAME_RE.match(name.lower()) or not _SAFE_VERSION_RE.match(version):
        return None
    return name, version


def _parse_pnpm_lock(
    path: str, text: str
) -> tuple[list[LockedPackage], list[DependencyProblem], bool, bool]:
    """Collect recognizable package keys and flag package entries we cannot interpret.

    The separate consistency flag remains false: this best-effort reader cannot prove
    manifest/lockfile consistency, even when every visible package key was recognized.
    """
    locked: list[LockedPackage] = []
    seen: set[tuple[str, str]] = set()
    in_packages = False
    entry_indent: int | None = None
    omitted = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line[0].isspace():
            in_packages = False
            entry_indent = None
            section = _PNPM_SECTION_RE.match(raw_line)
            if section is not None:
                value = section.group(1).strip()
                value = "" if value.startswith("#") else value.split(" #", 1)[0].strip()
                in_packages = not value
                if value not in ("", "{}", "[]", "null", "~"):
                    omitted = True
            continue
        if not in_packages:
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0 or raw_line[indent] == "\t":
            omitted = True
            continue
        if entry_indent is None:
            entry_indent = indent
        elif indent < entry_indent:
            # Inconsistent indentation cannot be interpreted confidently.
            entry_indent = indent
            omitted = True
        if indent != entry_indent:
            continue
        match = _PNPM_KEY_RE.match(raw_line[indent:])
        coordinate = _pnpm_coordinate(match.group(1)) if match is not None else None
        if coordinate is None:
            omitted = True
        elif coordinate not in seen:
            seen.add(coordinate)
            locked.append(LockedPackage(Ecosystem.NPM, coordinate[0], coordinate[1], path))
    return locked, [], False, omitted


# --------------------------------------------------------------------------------------
# Inventory builder
# --------------------------------------------------------------------------------------


def _pins_from_declarations(entries: list[DeclaredDependency], path: str) -> list[LockedPackage]:
    """Promote exact version pins declared by a manifest into locked package records."""
    pins: list[LockedPackage] = []
    for entry in entries:
        exact = entry.exact_version
        if exact is None:
            continue
        pins.append(LockedPackage(Ecosystem.PYPI, entry.name, exact, path))
    return pins


def _safe_json_loads(text: str) -> object:
    """Parse untrusted JSON, treating decode errors and pathological nesting as invalid."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None


def _safe_read_text(context: RepositoryContext, path: str) -> str | None:
    """Read a discovered file, returning None if it became unavailable during the scan."""
    try:
        return context.read_text(path)
    except (DiscoveryError, OversizedFileAccessError, SensitiveFileAccessError, OSError):
        return None


def _input_kind(name: str) -> tuple[Ecosystem, bool, bool] | None:
    """Return ecosystem and declaration/lockfile relevance for a supported input."""
    if name in _PY_MANIFEST_NAMES or _REQUIREMENTS_NAME_RE.match(name):
        # Python manifests can also provide exact pins for the locked inventory.
        return Ecosystem.PYPI, True, True
    if name == "package.json":
        return Ecosystem.NPM, True, False
    if name in _PYPROJECT_LOCKFILES:
        return Ecosystem.PYPI, False, True
    if name in _NPM_LOCKFILES:
        return Ecosystem.NPM, False, True
    return None


def build_dependency_inventory(context: RepositoryContext) -> DependencyInventory:
    """Parse every safely discovered manifest and lockfile into a normalized inventory."""
    declared: list[DeclaredDependency] = []
    locked: list[LockedPackage] = []
    problems: list[DependencyProblem] = []
    lockfiles: list[LockfileSummary] = []
    python_manifests: list[str] = []
    npm_manifests: list[str] = []
    gaps: list[DependencyInventoryGap] = []

    parsed = 0
    for item in context.files:
        if item.is_sensitive or item.is_oversized:
            continue
        if context.has_gitignore and context.gitignore.is_ignored(item.path, is_dir=False):
            continue

        path = item.path
        name = PurePosixPath(path).name
        # Unsupported formats are reported from their names, without reading binary data
        # or letting them consume the budget for supported inputs.
        if name in _UNSUPPORTED_NPM_LOCKFILES:
            problems.append(
                _problem(
                    DependencyProblemKind.UNSUPPORTED_LOCKFILE,
                    path,
                    f"`{name}` is not parsed by RepoLens; dependency vulnerability coverage "
                    "is unavailable for this lockfile format.",
                )
            )
            continue
        kind = _input_kind(name)
        if kind is None:
            continue
        ecosystem, affects_declarations, affects_lockfiles = kind
        is_requirements = bool(_REQUIREMENTS_NAME_RE.match(name))
        if parsed >= _MAX_PARSED_FILES:
            gaps.append(
                DependencyInventoryGap(
                    path,
                    ecosystem,
                    "eligible input(s) omitted after the 80-read limit",
                    affects_declarations,
                    affects_lockfiles,
                )
            )
            continue

        text = _safe_read_text(context, path)
        if text is None:
            gaps.append(
                DependencyInventoryGap(
                    path,
                    ecosystem,
                    "eligible input(s) could not be read",
                    affects_declarations,
                    affects_lockfiles,
                )
            )
            continue

        parsed += 1
        problem_count = len(problems)

        if name == "pyproject.toml":
            python_manifests.append(path)
            entries, file_problems = _parse_pyproject(path, text)
            declared.extend(entries)
            locked.extend(_pins_from_declarations(entries, path))
            problems.extend(file_problems)
        elif name == "Pipfile":
            python_manifests.append(path)
            entries, file_problems = _parse_pipfile(path, text)
            declared.extend(entries)
            locked.extend(_pins_from_declarations(entries, path))
            problems.extend(file_problems)
        elif name == "setup.cfg":
            python_manifests.append(path)
            entries, file_problems = _parse_setup_cfg(path, text)
            declared.extend(entries)
            locked.extend(_pins_from_declarations(entries, path))
            problems.extend(file_problems)
        elif is_requirements:
            python_manifests.append(path)
            entries, pins, file_problems = _parse_requirements_file(path, text)
            declared.extend(entries)
            locked.extend(pins)
            problems.extend(file_problems)
            # A requirements file only acts as a lockfile when every requirement is pinned.
            fully_pinned = bool(entries) and len(pins) == len(entries)
            lockfiles.append(
                LockfileSummary(
                    path=path,
                    ecosystem=Ecosystem.PYPI,
                    complete=fully_pinned,
                    package_count=len(pins),
                )
            )
        elif name == "package.json":
            npm_manifests.append(path)
            entries, file_problems = _parse_package_json(path, text)
            declared.extend(entries)
            problems.extend(file_problems)
        elif name in _PYPROJECT_LOCKFILES:
            if name == "Pipfile.lock":
                file_locked, file_problems, complete = _parse_pipfile_lock(path, text)
            else:
                file_locked, file_problems, complete = _parse_toml_lockfile(path, text)
            locked.extend(file_locked)
            problems.extend(file_problems)
            lockfiles.append(
                LockfileSummary(
                    path=path,
                    ecosystem=Ecosystem.PYPI,
                    complete=complete,
                    package_count=len(file_locked),
                )
            )
        elif name in _NPM_LOCKFILES:
            omitted = False
            if name == "yarn.lock":
                file_locked, file_problems, complete = _parse_yarn_lock(path, text)
            elif name == "pnpm-lock.yaml":
                file_locked, file_problems, complete, omitted = _parse_pnpm_lock(path, text)
            else:
                file_locked, file_problems, complete, omitted = _parse_package_lock(path, text)
            locked.extend(file_locked)
            problems.extend(file_problems)
            lockfiles.append(
                LockfileSummary(
                    path=path,
                    ecosystem=Ecosystem.NPM,
                    complete=complete,
                    package_count=len(file_locked),
                )
            )
            if omitted:
                reason = (
                    "pnpm lockfile(s) with uninterpretable package entries"
                    if name == "pnpm-lock.yaml"
                    else "npm lockfile(s) with packages beyond the nesting limit"
                )
                gaps.append(DependencyInventoryGap(path, ecosystem, reason, False, True))

        if any(
            problem.kind is not DependencyProblemKind.UNSUPPORTED_LOCKFILE
            for problem in problems[problem_count:]
        ):
            gaps.append(
                DependencyInventoryGap(
                    path,
                    ecosystem,
                    "dependency input(s) could not be fully parsed",
                    affects_declarations,
                    affects_lockfiles,
                )
            )

    return DependencyInventory(
        declared=tuple(declared),
        locked=tuple(locked),
        problems=tuple(problems),
        lockfiles=tuple(lockfiles),
        python_manifest_paths=tuple(python_manifests),
        npm_manifest_paths=tuple(npm_manifests),
        gaps=tuple(gaps),
    )
