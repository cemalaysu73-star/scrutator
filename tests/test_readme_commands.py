import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scrutator import cli

README = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
runner = CliRunner()
COMMANDS = {"scan", "keygen", "export", "verify", "diff", "watch", "risk", "ai", "doctor", "packs", "list", "validate", "manifest"}


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


@pytest.mark.parametrize("path, options, line", documented_commands())
def test_every_documented_command_and_option_exists(path, options, line):
    assert path, f"not a command: {line}"
    result = runner.invoke(cli.app, [*path, "--help"])
    assert result.exit_code == 0, line
    text = re.sub(r"\s+", " ", result.output)
    for option in options:
        assert option in text, f"{option} is not an option of `scrutator {' '.join(path)}` ({line})"
