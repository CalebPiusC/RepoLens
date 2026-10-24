"""Unit tests for offline Python/npm manifest and lockfile parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repolens.analyzers.dependencies import npm_spec_satisfied
from repolens.config import ScanConfig
from repolens.dependencies import (
    DependencyProblemKind,
    Ecosystem,
    build_dependency_inventory,
    normalize_pypi_name,
)
from repolens.discovery import RepositoryContext, discover_repository


def _context(tmp_path: Path, files: dict[str, str], name: str = "repo") -> RepositoryContext:
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return discover_repository(root, ScanConfig())


def test_requirements_file_parsing_handles_all_line_shapes(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "requirements.txt": (
                "# production requirements\n"
                "-r base.txt\n"
                "--index-url https://pypi.org/simple\n"
                "-e .\n"
                "git+https://github.com/example/dep.git#egg=dep\n"
                "requests>=2.31,<3\n"
                "flask==3.0.0\n"
                "uvicorn[standard]==0.30.1  # web server\n"
                "broken requirement line\n"
                "numpy\n"
            )
        },
    )
    inventory = build_dependency_inventory(context)

    names = {dependency.name for dependency in inventory.declared}
    assert names == {"requests", "flask", "uvicorn", "numpy"}
    assert inventory.problems[0].kind is DependencyProblemKind.INVALID_REQUIREMENT
    assert inventory.problems[0].line == 9
    locked = {(package.name, package.version) for package in inventory.locked}
    assert ("flask", "3.0.0") in locked
    assert ("uvicorn", "0.30.1") in locked
    # Partially pinned requirements must not count as a lockfile.
    assert inventory.has_python_lockfile() is False


def test_fully_pinned_requirements_counts_as_lockfile(tmp_path: Path) -> None:
    context = _context(tmp_path, {"requirements.txt": "flask==3.0.0\nrequests==2.32.3\n"})
    inventory = build_dependency_inventory(context)
    assert inventory.has_python_lockfile() is True


def test_pyproject_pep621_poetry_and_groups(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "pyproject.toml": (
                "[project]\n"
                'name = "demo"\n'
                "dependencies = [\n"
                '  "requests>=2.31",\n'
                '  "invalid specifier here",\n'
                "]\n"
                "[project.optional-dependencies]\n"
                'dev = ["pytest>=8"]\n'
                "[dependency-groups]\n"
                'lint = ["ruff>=0.6"]\n'
                "[tool.poetry.dependencies]\n"
                'python = "^3.11"\n'
                'click = "^8.1"\n'
                'local = { path = "../local" }\n'
                "[tool.poetry.group.docs.dependencies]\n"
                'mkdocs = "^1.6"\n'
            )
        },
    )
    inventory = build_dependency_inventory(context)

    declared = {(dep.name, dep.specifier, dep.dev) for dep in inventory.declared}
    assert ("requests", ">=2.31", False) in declared
    assert ("pytest", ">=8", True) in declared
    assert ("ruff", ">=0.6", True) in declared
    assert ("click", "^8.1", False) in declared
    assert ("mkdocs", "^1.6", True) in declared
    assert all(name != "python" and name != "local" for name, _, _ in declared)
    assert any(
        problem.kind is DependencyProblemKind.INVALID_REQUIREMENT for problem in inventory.problems
    )


def test_pipfile_and_setup_cfg_parsing(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "Pipfile": (
                "[packages]\n"
                'django = "==4.2.11"\n'
                'requests = "*"\n'
                "[dev-packages]\n"
                'pytest = "==8.2.0"\n'
            ),
            "setup.cfg": (
                "[metadata]\n"
                "name = demo\n"
                "[options]\n"
                "install_requires =\n"
                "    click>=8.1\n"
                "    jinja2\n"
                "[options.extras_require]\n"
                "test =\n"
                "    pytest>=8\n"
            ),
        },
    )
    inventory = build_dependency_inventory(context)

    declared = {(dep.name, dep.specifier, dep.dev) for dep in inventory.declared}
    assert ("django", "==4.2.11", False) in declared
    assert ("requests", "*", False) in declared
    assert ("pytest", "==8.2.0", True) in declared
    assert ("click", ">=8.1", True) in declared
    assert ("jinja2", "", True) in declared
    assert any(
        package.name == "django" and package.version == "4.2.11" for package in inventory.locked
    )


def test_pipfile_and_setup_cfg_malformed_reports_problem(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "Pipfile": "[packages\nbroken\n",
            "setup.cfg": "[options\nbroken\n",
        },
    )
    inventory = build_dependency_inventory(context)
    malformed_paths = {
        problem.path
        for problem in inventory.problems
        if problem.kind is DependencyProblemKind.MALFORMED_MANIFEST
    }
    assert malformed_paths == {"Pipfile", "setup.cfg"}


def test_package_json_filters_local_and_workspace_specs(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "name": "demo",
                    "dependencies": {
                        "react": "^18.2.0",
                        "workspace-lib": "workspace:*",
                        "local": "file:../local",
                        "remote": "github:user/repo",
                    },
                    "devDependencies": {"vitest": "^2.0.0"},
                }
            )
        },
    )
    inventory = build_dependency_inventory(context)
    declared = {(dep.name, dep.dev) for dep in inventory.declared}
    assert declared == {("react", False), ("vitest", True)}


def test_package_lock_v3_and_v1_parsing(tmp_path: Path) -> None:
    v3 = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"react": "^18.2.0"}},
            "node_modules/react": {"version": "18.3.1"},
            "node_modules/@types/node": {"version": "20.14.0"},
            "node_modules/a/node_modules/nested": {"version": "1.0.0"},
        },
    }
    context = _context(tmp_path, {"package-lock.json": json.dumps(v3)}, name="v3")
    inventory = build_dependency_inventory(context)
    locked = {(package.name, package.version) for package in inventory.locked}
    assert locked == {
        ("react", "18.3.1"),
        ("@types/node", "20.14.0"),
        ("nested", "1.0.0"),
    }
    assert inventory.lockfiles[0].complete is True

    v1 = {
        "lockfileVersion": 1,
        "dependencies": {
            "react": {
                "version": "18.2.0",
                "dependencies": {"loose-envify": {"version": "1.4.0"}},
            }
        },
    }
    context = _context(tmp_path, {"package-lock.json": json.dumps(v1)}, name="v1")
    inventory = build_dependency_inventory(context)
    locked = {(package.name, package.version) for package in inventory.locked}
    assert locked == {("react", "18.2.0"), ("loose-envify", "1.4.0")}


def test_yarn_lock_classic_and_berry_parsing(tmp_path: Path) -> None:
    classic = (
        '# comment\n"@types/node@^20.0.0", "@types/node@^20.1.0":\n'
        '  version "20.14.0"\n  resolved "https://registry.yarnpkg.com/x"\n\n'
        '"react@^18.0.0":\n  version "18.3.1"\n'
    )
    context = _context(tmp_path, {"yarn.lock": classic}, name="classic")
    inventory = build_dependency_inventory(context)
    assert {(p.name, p.version) for p in inventory.locked} == {
        ("@types/node", "20.14.0"),
        ("react", "18.3.1"),
    }
    assert inventory.lockfiles[0].complete is True

    berry = '"react@npm:^18.0.0":\n  version: 18.3.1\n'
    context = _context(tmp_path, {"yarn.lock": berry}, name="berry")
    inventory = build_dependency_inventory(context)
    assert {(p.name, p.version) for p in inventory.locked} == {("react", "18.3.1")}


def test_pnpm_lock_is_best_effort_and_incomplete(tmp_path: Path) -> None:
    lock = (
        "lockfileVersion: '9.0'\n\n"
        "importers:\n\n"
        "  .:\n"
        "    dependencies:\n"
        "      react:\n"
        "        specifier: ^18.0.0\n"
        "        version: 18.3.1\n\n"
        "packages:\n\n"
        "  react@18.3.1:\n"
        "    resolution: {integrity: sha512-x}\n\n"
        "  react-dom@18.3.1(react@18.3.1):\n"
        "    resolution: {integrity: sha512-y}\n"
    )
    context = _context(tmp_path, {"pnpm-lock.yaml": lock})
    inventory = build_dependency_inventory(context)
    assert {(p.name, p.version) for p in inventory.locked} == {
        ("react", "18.3.1"),
        ("react-dom", "18.3.1"),
    }
    assert inventory.lockfiles[0].complete is False


def test_python_lockfiles_and_malformed_lockfile(tmp_path: Path) -> None:
    poetry = (
        '[[package]]\nname = "click"\nversion = "8.1.7"\n'
        '[[package]]\nname = "requests"\nversion = "2.32.3"\n'
    )
    context = _context(tmp_path, {"poetry.lock": poetry}, name="poetry")
    inventory = build_dependency_inventory(context)
    assert {(p.name, p.version) for p in inventory.locked} == {
        ("click", "8.1.7"),
        ("requests", "2.32.3"),
    }

    pipfile_lock = {
        "_meta": {},
        "default": {"flask": {"version": "==3.0.0"}},
        "develop": {"pytest": {"version": "==8.2.0"}},
    }
    context = _context(tmp_path, {"Pipfile.lock": json.dumps(pipfile_lock)}, name="pipfile")
    inventory = build_dependency_inventory(context)
    assert {(p.name, p.version) for p in inventory.locked} == {
        ("flask", "3.0.0"),
        ("pytest", "8.2.0"),
    }

    context = _context(tmp_path, {"package-lock.json": "{broken"}, name="broken")
    inventory = build_dependency_inventory(context)
    assert inventory.problems[0].kind is DependencyProblemKind.MALFORMED_LOCKFILE
    assert inventory.problems[0].line == 1


def test_unsupported_lockfile_is_reported(tmp_path: Path) -> None:
    context = _context(tmp_path, {"bun.lockb": "binary"})
    inventory = build_dependency_inventory(context)
    assert inventory.problems[0].kind is DependencyProblemKind.UNSUPPORTED_LOCKFILE
    assert inventory.locked == ()


def test_unique_packages_deduplicates_and_sorts(tmp_path: Path) -> None:
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/zeta": {"version": "2.0.0"},
            "node_modules/alpha": {"version": "1.0.0"},
            "node_modules/broken": {"version": "not a version"},
        },
    }
    pipfile = {"default": {"Django": {"version": "==4.2.0"}}}
    context = _context(
        tmp_path,
        {
            "package-lock.json": json.dumps(lock),
            "Pipfile.lock": json.dumps(pipfile),
            "requirements.txt": "django==4.2.0\n",
        },
    )
    inventory = build_dependency_inventory(context)
    unique = inventory.unique_packages()
    assert unique == (
        ("Django", "4.2.0", Ecosystem.PYPI),
        ("alpha", "1.0.0", Ecosystem.NPM),
        ("zeta", "2.0.0", Ecosystem.NPM),
    )


def test_sensitive_and_ignored_manifests_are_skipped(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            ".gitignore": "ignored-dir/\n",
            "ignored-dir/requirements.txt": "flask==3.0.0\n",
            ".env": "TOKEN=secret\n",
        },
    )
    inventory = build_dependency_inventory(context)
    assert inventory.declared == ()
    assert inventory.python_manifest_paths == ()


def test_lockfiles_for_dir_groups_by_parent(tmp_path: Path) -> None:
    context = _context(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"react": "^18.0.0"}}),
            "package-lock.json": json.dumps(
                {"lockfileVersion": 3, "packages": {"node_modules/react": {"version": "18.3.1"}}}
            ),
            "packages/web/package.json": json.dumps({"dependencies": {"vue": "^3.0.0"}}),
            "packages/web/package-lock.json": json.dumps(
                {"lockfileVersion": 3, "packages": {"node_modules/vue": {"version": "3.5.0"}}}
            ),
        },
    )
    inventory = build_dependency_inventory(context)

    root_locks = inventory.lockfiles_for_dir(Ecosystem.NPM, "")
    web_locks = inventory.lockfiles_for_dir(Ecosystem.NPM, "packages/web")
    assert [lock.path for lock in root_locks] == ["package-lock.json"]
    assert [lock.path for lock in web_locks] == ["packages/web/package-lock.json"]
    assert inventory.locked_names_for_dir(Ecosystem.NPM, "") == {"react"}
    assert inventory.locked_names_for_dir(Ecosystem.NPM, "packages/web") == {"vue"}


def test_normalize_pypi_name_follows_pep503() -> None:
    assert normalize_pypi_name("Zope.Interface") == "zope-interface"
    assert normalize_pypi_name("my_pkg") == "my-pkg"


@pytest.mark.parametrize(
    ("version", "specifier", "expected"),
    [
        ("18.3.1", "^18.2.0", True),
        ("19.0.0", "^18.2.0", False),
        ("18.1.0", "^18.2.0", False),
        ("18.3.1", "~18.3.0", True),
        ("18.4.0", "~18.3.0", False),
        ("1.2.3", "1.2.3", True),
        ("1.2.4", "1.2.3", False),
        ("1.2.3", "=1.2.3", True),
        ("0.2.5", "^0.2.0", True),
        ("0.3.0", "^0.2.0", False),
        ("0.0.5", "^0.0.3", False),
        ("18.3.1", ">=18.0.0", None),
        ("18.3.1", "18.x", None),
        ("18.3.1", "*", None),
        ("18.3.1", "", None),
        ("18.3.1", "^1.0.0 || ^2.0.0", None),
        ("18.3.1", "npm:other@^1.0.0", None),
        ("latest", "^1.0.0", None),
    ],
)
def test_npm_spec_satisfied(version: str, specifier: str, expected: bool | None) -> None:
    assert npm_spec_satisfied(version, specifier) is expected
