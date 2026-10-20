"""What a wheel must carry and what `--version` reports. The wheel itself is built and installed into a fresh
virtual environment by tools/wheel_smoke.py (and by CI); these checks keep the inputs of that build honest."""

import re
import tomllib
from importlib import resources
from pathlib import Path

from typer.testing import CliRunner

import scrutator
from scrutator import cli

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "scrutator"


def test_version_flag_prints_the_package_version():
    result = CliRunner().invoke(cli.app, ["--version"])
    assert result.exit_code == 0 and result.output.strip() == f"scrutator {scrutator.__version__}"


def test_the_project_version_and_the_package_version_agree():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == scrutator.__version__


def test_package_data_is_inside_the_package_and_found_through_importlib_resources():
    data = [p for p in PACKAGE.rglob("*") if p.is_file() and p.suffix not in {".py", ".pyc"} and "__pycache__" not in p.parts]
    assert {p.name for p in data} >= {"template.html", "manifest.json", "providers.yaml", "takeover.yaml", "signals.yaml", "playbooks.yaml"}
    assert resources.files("scrutator.report").joinpath("template.html").is_file()
    assert resources.files("scrutator.packs").joinpath("data").joinpath("manifest.json").is_file()


def test_no_gitignore_pattern_swallows_package_data():
    """hatchling leaves out files git ignores; a pattern like `keys/` or `*.db` that matches package data would
    produce a wheel that works from a checkout and fails when installed."""
    patterns = [line.strip() for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    data = [p.relative_to(ROOT).as_posix() for p in PACKAGE.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"]
    for pattern in patterns:
        regex = re.compile(
            "(^|/)" + re.escape(pattern.rstrip("/")).replace(r"\*", "[^/]*") + ("/" if pattern.endswith("/") else "$") + ("" if pattern.endswith("/") else "")
        )
        hit = [path for path in data if regex.search(path)]
        assert not hit, f".gitignore pattern {pattern!r} matches package files: {hit[:3]}"
