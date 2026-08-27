"""Guards on the things that only break once the app is packaged.

These failures are invisible during development - everything works when you
run `python -m sitescope` - and only appear when someone double-clicks the
built .exe. That is far too late to find out, so they are checked here.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ENTRY_POINT = ROOT / "main.py"
SPEC = ROOT / "build" / "sitescope.spec"


def test_entry_point_exists():
    assert ENTRY_POINT.exists(), "main.py is the entry point PyInstaller builds from"


def test_entry_point_runs_as_a_plain_script():
    """The exact failure mode PyInstaller causes.

    PyInstaller executes its entry script as ``__main__``, leaving
    ``__package__`` empty, so any relative import in that script raises
    "attempted relative import with no known parent package" the moment the
    .exe is launched. Running main.py directly reproduces that condition.
    """
    result = subprocess.run(
        [sys.executable, str(ENTRY_POINT), "--version"],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT),
    )

    assert result.returncode == 0, (
        f"main.py failed when run as a script, so the packaged .exe would not "
        f"start either.\nstderr:\n{result.stderr}"
    )
    assert "SiteScope" in result.stdout


def test_module_entry_point_still_works():
    """`python -m sitescope` must keep working for development use."""
    result = subprocess.run(
        [sys.executable, "-m", "sitescope", "--version"],
        capture_output=True, text=True, timeout=60, cwd=str(ROOT),
    )
    assert result.returncode == 0, result.stderr
    assert "SiteScope" in result.stdout


def _spec_analysis_scripts() -> list[str]:
    """The entry scripts passed to Analysis() in the spec file.

    Parsed rather than string-matched so that a comment mentioning the unsafe
    path does not count as using it.
    """
    tree = ast.parse(SPEC.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "Analysis"
                and node.args):
            first = node.args[0]
            if isinstance(first, (ast.List, ast.Tuple)):
                return [e.value for e in first.elts if isinstance(e, ast.Constant)]
    raise AssertionError("No Analysis(...) call found in build/sitescope.spec")


def test_spec_builds_from_the_safe_entry_point():
    """The spec must build from main.py, not from sitescope/__main__.py."""
    scripts = _spec_analysis_scripts()

    assert scripts == ["../main.py"], (
        f"build/sitescope.spec should build from ../main.py, got {scripts}. "
        f"Building directly from sitescope/__main__.py breaks its relative "
        f"imports in the packaged executable."
    )


@pytest.mark.parametrize("relative", [
    "sitescope/web/templates",
    "sitescope/web/static",
    "sitescope/web/static/css/app.css",
    "sitescope/web/static/js/core.js",
    "sitescope/web/static/js/charts.js",
    "build/sitescope.ico",
])
def test_bundled_resources_are_present(relative):
    """Everything the spec bundles must actually exist in the repository."""
    assert (ROOT / relative).exists(), f"{relative} is referenced by the build but missing"


def test_every_check_module_is_a_declared_hidden_import():
    """Checks are imported dynamically, so PyInstaller cannot see them.

    A new check module that is not listed in the spec's hiddenimports would be
    silently dropped from the .exe, and that check would simply never run -
    a scanner quietly missing a vulnerability class.
    """
    spec_text = SPEC.read_text(encoding="utf-8")
    checks_dir = ROOT / "sitescope" / "scanner" / "checks"

    for module in sorted(checks_dir.glob("*.py")):
        if module.stem == "__init__":
            continue
        dotted = f"sitescope.scanner.checks.{module.stem}"
        assert dotted in spec_text, (
            f"{dotted} is not in hiddenimports in build/sitescope.spec, so it "
            f"would be missing from the packaged application"
        )


def test_runtime_dependencies_are_declared():
    """Anything imported at runtime must be in requirements.txt."""
    declared = {
        line.split("#")[0].split(">")[0].split("=")[0].split("<")[0].strip().lower()
        for line in (ROOT / "requirements.txt").read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }

    third_party = set()
    stdlib = set(sys.stdlib_module_names)

    for path in (ROOT / "sitescope").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    third_party.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    third_party.add(node.module.split(".")[0])

    third_party -= stdlib
    third_party -= {"sitescope", "__future__"}
    # urllib3 arrives as a dependency of requests rather than being declared.
    third_party -= {"urllib3"}

    missing = {name for name in third_party if name.lower() not in declared}
    assert not missing, f"imported at runtime but not in requirements.txt: {sorted(missing)}"
