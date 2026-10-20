import re
from pathlib import Path

import pytest
from ablation import BUDGETS, PUBLISHED
from attrlab import TRUTH, run_lab
from typer.testing import CliRunner

from scrutator import cli
from scrutator.attribution import SIGNALS, evaluate

README = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
SOURCES_PAGE = (Path(__file__).parent.parent / "docs" / "sources.md").read_text(encoding="utf-8")
runner = CliRunner()
COMMANDS = {
    "scan", "keygen", "export", "verify", "diff", "watch", "risk", "ai", "doctor", "packs", "list", "validate", "manifest",
    "candidates", "attribution", "promote", "mcp", "sources", "bench", "protect-key",
}
# options of the program itself, not of a command (`scrutator --version`)
ROOT_OPTIONS = {"--version", "--help"}


def documented_commands():
    """Every `scrutator ...` line in the README's bash blocks, split into command words and options."""
    found = []
    for block in re.findall(r"```bash\n(.*?)```", README, re.S):
        for line in block.splitlines():
            line = line.split("#")[0].strip()
            if not line.startswith("scrutator "):
                continue
            words = line.split()[1:]
            path = []
            for word in words:
                if word in COMMANDS:
                    path.append(word)
                else:
                    break
            options = sorted({w for w in words if w.startswith("--")})
            found.append((path, options, line))
    return found


def test_the_readme_documents_the_new_commands():
    paths = {tuple(path) for path, _, _ in documented_commands()}
    assert {("risk",), ("packs", "list"), ("packs", "validate"), ("scan",), ("verify",)} <= paths
    assert {("candidates",), ("attribution",), ("promote",), ("mcp",)} <= paths


def test_the_readme_shows_the_new_scan_options():
    options = {option for _, found, _ in documented_commands() for option in found}
    assert {"--attribution", "--allow-scan", "--allow-promote", "--scope", "--min-band", "--entity"} <= options


@pytest.mark.parametrize("path, options, line", documented_commands())
def test_every_documented_command_and_option_exists(path, options, line):
    if not path and options and set(options) <= ROOT_OPTIONS:
        result = runner.invoke(cli.app, options)
        assert result.exit_code == 0, line
        return
    assert path, f"not a command: {line}"
    result = runner.invoke(cli.app, [*path, "--help"])
    assert result.exit_code == 0, line
    text = re.sub(r"\s+", " ", result.output)
    for option in options:
        assert option in text, f"{option} is not an option of `scrutator {' '.join(path)}` ({line})"


def test_the_signal_table_is_the_one_the_code_uses():
    for kind, (weight, _) in SIGNALS.items():
        assert f"| `{kind}` | {weight:.2f} |" in README, kind
    assert len(SIGNALS) == 10


async def test_the_published_lab_table_is_what_the_lab_measures(http, tmp_path):
    lab = await run_lab(http, tmp_path)
    for band, row in evaluate(lab.report["attribution"], TRUTH).items():
        expected = f"| {band} | {row['count']} | {row['true']} | {row['precision']:.2f} | {row['or_better_precision']:.2f} | {row['or_better_recall']:.2f} |"
        assert expected in README, expected


def test_the_published_ablation_table_is_what_the_harness_measures():
    for budget in BUDGETS:
        (without, with_) = PUBLISHED[budget]
        row = f"| {budget} | {without[0]} | {with_[0]} | {without[1]} | {with_[1]} |"
        assert row in README, row


def test_the_mcp_tools_in_the_readme_are_the_tools_the_server_offers():
    from scrutator.mcp_tools import ToolSet

    offered = {name for name in ("list_candidates", "attribution", "risk", "verify_bundle", "scan", "promote_candidate") if hasattr(ToolSet, name)}
    documented = set(re.findall(r"^\| `(\w+)` \| (?:always|`--allow-\w+`) \|", README, re.M))
    assert documented == offered


def test_every_source_with_terms_is_in_the_sources_table():
    """A module that carries a licence note must be documented, with its host, in the sources table (docs/sources.md,
    where the README's table moved in R4)."""
    import inspect
    import re

    from scrutator.modules.registry import load_builtin_modules

    documented = 0
    for module in load_builtin_modules():
        if not module.licence_note:
            continue
        documented += 1
        hosts = set(re.findall(r"https://([a-z0-9.-]+)", inspect.getsource(type(module))))
        if module.opt_in:
            # the opt-in modules contact the organisation's own site, and the platform hosts their licence note names
            hosts |= set(re.findall(r"\b((?:[a-z0-9-]+\.)+(?:com|org|social|co))\b", module.licence_note))
            assert f"`{module.name}`" in SOURCES_PAGE, module.name
        else:
            assert hosts, module.name
        for host in hosts:
            assert host in SOURCES_PAGE, f"{module.name}: {host} is not in the sources table of docs/sources.md"
    assert documented >= 5
