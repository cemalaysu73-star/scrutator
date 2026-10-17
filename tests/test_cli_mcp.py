import sys

from typer.testing import CliRunner

from scrutator import cli, mcp_server

runner = CliRunner()


def scope(tmp_path, text="domains:\n  - example.com\n"):
    path = tmp_path / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_enabling_scan_or_promotion_needs_a_scope_file(tmp_path):
    for flag in ("--allow-scan", "--allow-promote"):
        result = runner.invoke(cli.app, ["mcp", "--db", str(tmp_path / "x.db"), flag])
        assert result.exit_code == 2 and "--scope" in result.output, flag


def test_a_scope_file_that_cannot_be_used_is_refused_before_serving(tmp_path, monkeypatch):
    served = []
    monkeypatch.setattr(mcp_server, "serve", served.append)
    result = runner.invoke(cli.app, ["mcp", "--scope", str(scope(tmp_path, "websites: [x]\n"))])
    assert result.exit_code == 2 and "cannot load scope" in result.output
    assert runner.invoke(cli.app, ["mcp", "--scope", str(tmp_path / "missing.yaml")]).exit_code == 2
    assert served == []


def test_the_flags_become_the_tool_sets_permissions(tmp_path, monkeypatch):
    served = []
    monkeypatch.setattr(mcp_server, "serve", served.append)
    assert runner.invoke(cli.app, ["mcp", "--db", str(tmp_path / "x.db")]).exit_code == 0
    assert runner.invoke(cli.app, ["mcp", "--db", str(tmp_path / "x.db"), "--scope", str(scope(tmp_path)), "--allow-scan", "--allow-promote"]).exit_code == 0
    plain, full = served
    assert (plain.allow_scan, plain.allow_promote, plain.scope_file) == (False, False, None)
    assert (full.allow_scan, full.allow_promote) == (True, True) and full.scope_file.name == "scope.yaml" and full.db.name == "x.db"


def test_without_the_sdk_the_command_says_how_to_install_it(tmp_path, monkeypatch):
    for name in ("mcp", "mcp.server"):  # `import mcp.server` now raises ImportError, as when it is not installed
        monkeypatch.setitem(sys.modules, name, None)
    result = runner.invoke(cli.app, ["mcp", "--db", str(tmp_path / "x.db")])
    assert result.exit_code == 2 and 'pip install "scrutator[mcp]"' in result.output


def test_help_describes_the_safe_defaults():
    out = " ".join(runner.invoke(cli.app, ["mcp", "--help"]).output.split())
    assert "Read-only tools by default" in out and "--allow-scan" in out and "--allow-promote" in out and "--scope" in out
