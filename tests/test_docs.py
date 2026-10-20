"""The documentation is held to the program: links resolve, the sources table is the one `scrutator sources` prints,
and every `scrutator ...` command line shown in a code block names a command and options that exist."""

import json
import re
import shlex
from pathlib import Path

import pytest
import typer.main
from typer.testing import CliRunner

from scrutator import cli

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md", ROOT / "CODE_OF_CONDUCT.md", ROOT / "RESPONSIBLE_USE.md",
        ROOT / "demo" / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
PAGES = [p for p in DOCS if p.exists()]


def slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    out = set()
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("#"):
            out.add(slug(line.lstrip("#")))
    return out


def test_the_expected_pages_exist():
    names = {p.name for p in PAGES}
    for required in ("README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "quickstart.md", "concepts.md", "reading-a-report.md",
                     "proof-bundles.md", "sources.md", "ai-and-privacy.md", "mcp.md", "knowledge-packs.md", "security.md", "benchmarks.md"):
        assert required in names, required


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_relative_link_resolves(page):
    text = page.read_text(encoding="utf-8")
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    problems = []
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if re.match(r"[a-z]+://|mailto:", target):
            continue
        path, _, fragment = target.partition("#")
        resolved = (page.parent / path).resolve() if path else page
        if not resolved.exists():
            problems.append(f"{target}: no such file")
        elif fragment and resolved.suffix == ".md" and fragment not in anchors(resolved):
            problems.append(f"{target}: no such heading")
    assert problems == []


def table_rows(path: Path, first_header: str) -> list[list[str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f"| {first_header} |"))
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip() for cell in re.split(r"(?<!\\)\|", line.strip().strip("|"))])
    return rows


def test_the_sources_table_is_the_list_scrutator_sources_prints(tmp_path):
    result = CliRunner().invoke(cli.app, ["sources", "--json", "--db", str(tmp_path / "none.db")])
    assert result.exit_code == 0, result.output
    live = {row["source"]: row for row in json.loads(result.output)}
    documented = {}
    for cells in table_rows(ROOT / "docs" / "sources.md", "Module"):
        documented[cells[0].strip("`")] = cells
    assert set(documented) == set(live), (sorted(set(documented) ^ set(live)))
    for name, cells in documented.items():
        row = live[name]
        access = cells[1].replace("`", "")
        assert access == row["kind"], (name, access, row["kind"])
        assert (cells[2] == "yes") == row["noncommercial"], name
        assert (cells[3] == "yes") == row["replayable"], name


def find_command(group, words: list[str]):
    command, used = group, 0
    for word in words:
        if hasattr(command, "commands") and word in command.commands:  # typer vendors click: no isinstance
            command, used = command.commands[word], used + 1
        else:
            break
    return command, used


def command_lines(page: Path):
    fenced = False
    for line in page.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        stripped = line.strip()
        if fenced and stripped.startswith(("scrutator ", "$ scrutator ")):
            yield stripped.removeprefix("$ ")


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_command_line_in_a_code_block_uses_a_real_command_and_real_options(page):
    group = typer.main.get_command(cli.app)
    problems = []
    for line in command_lines(page):
        words = shlex.split(line.split("  #")[0].split(" # ")[0], posix=True)[1:]
        if not words or words[0].startswith(("<", "-")):
            if words and words[0] == "--version":
                continue
            continue
        command, used = find_command(group, [w for w in words if not w.startswith("-")][:2])
        if command is group:
            problems.append(f"{line!r}: no such command")
            continue
        known = {opt for param in command.params for opt in [*param.opts, *param.secondary_opts]}
        for word in words:
            if word.startswith("--") and word.split("=")[0] not in known:
                problems.append(f"{line!r}: {word} is not an option of `{command.name}`")
    assert problems == []
