"""tools/sbom.py describes the environment it runs in: scrutator, its declared dependencies at their installed
versions, and a dependency graph whose references all resolve."""

import importlib.util
import sys
from importlib import metadata
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "tools" / "sbom.py"


def load():
    spec = importlib.util.spec_from_file_location("scrutator_sbom", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_sbom_lists_scrutator_and_its_installed_dependencies():
    bom = load().build("scrutator")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    top = bom["metadata"]["component"]
    assert top["name"] == "scrutator" and top["version"] == metadata.version("scrutator")
    names = {c["name"]: c for c in bom["components"]}
    for required in ("httpx", "pydantic", "typer", "dnspython", "pyyaml", "cryptography"):
        assert names[required]["version"] == metadata.version(required)
        assert names[required]["purl"] == f"pkg:pypi/{required}@{metadata.version(required)}"
    refs = {top["bom-ref"], *(c["bom-ref"] for c in bom["components"])}
    for row in bom["dependencies"]:
        assert row["ref"] in refs
        assert set(row["dependsOn"]) <= refs


def test_an_extra_adds_its_packages_only_when_asked():
    tool = load()
    without = {c["name"] for c in tool.build("scrutator")["components"]}
    with_mcp = {c["name"] for c in tool.build("scrutator", {"mcp"})["components"]}
    assert "mcp" not in without
    assert "mcp" in with_mcp


def test_markers_are_evaluated_for_this_interpreter():
    tool = load()
    here = f"{sys.version_info[0]}.{sys.version_info[1]}"
    assert tool._marker_holds(f'python_version >= "{here}"', set())
    assert not tool._marker_holds('python_version < "3.0"', set())
    assert tool._marker_holds('extra == "mcp"', {"mcp"})
    assert not tool._marker_holds('extra == "dev"', {"mcp"})
    assert tool._marker_holds("something_unknown(", set())  # a form it cannot read lists the package
