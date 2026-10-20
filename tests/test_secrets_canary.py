"""R4 A1: a canary key in every SCRUTATOR_*_KEY variable must never come back out of the tool.

One scan through the MCP tool layer with all three keyed sources answering (one of them failing, one paging), with
every logger captured at DEBUG (the MCP SDK configures the root logger at INFO, and httpx logs each request URL
there; Shodan wants its key in the URL). Then every surface a user, a client or a reader of a bundle can see is
searched for the canary: logs, MCP results, the report, the HTML, the signed bundle, the database file, the audit
log, the CLI's listings and `scrutator sources` (text and JSON)."""

import json
import logging
import zipfile
from contextlib import asynccontextmanager

import httpx
import pytest
import respx
from typer.testing import CliRunner

from scrutator import cli
from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.writer import create_bundle
from scrutator.keys import install_log_redaction
from scrutator.mcp_tools import ToolSet
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.report import build_report, render_html, render_json
from scrutator.store import Store

CANARY = "CANARY-7f3a9c-SECRET-KEY-do-not-print"
VARIABLES = ("SCRUTATOR_VIRUSTOTAL_KEY", "SCRUTATOR_SECURITYTRAILS_KEY", "SCRUTATOR_SHODAN_KEY")
FORMS = (CANARY, "CANARY-7f3a9c")  # the whole key, and a prefix that would show a truncated leak


class Resolver:
    async def lookup(self, name, rtype):
        return ["192.0.2.10"] if rtype == "A" and name.endswith("example.com") else []


def leaked(text: str) -> bool:
    return any(form in text for form in FORMS)


@pytest.fixture
def canary_env(monkeypatch):
    for name in VARIABLES:
        monkeypatch.setenv(name, CANARY)


async def test_a_canary_key_never_leaves_the_tool(canary_env, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)  # what a client's log file would hold if it logged everything
    scope = tmp_path / "scope.yaml"
    scope.write_text("domains:\n  - example.com\n", encoding="utf-8")
    db = tmp_path / "scrutator.db"
    modules = [m for m in load_builtin_modules() if m.name in {"virustotal", "securitytrails", "shodan", "dns"}]

    @asynccontextmanager
    async def context():
        async with httpx.AsyncClient(follow_redirects=True) as http:
            yield ModuleContext(http=http, resolver=Resolver())

    tools = ToolSet(db, scope_file=scope, allow_scan=True, context=context, modules=modules)
    with respx.mock() as router:
        router.get("https://www.virustotal.com/api/v3/domains/example.com/subdomains").mock(
            return_value=httpx.Response(200, json={"data": [{"id": "vt.example.com"}], "meta": {}})
        )
        # an error whose text quotes a URL with the key in it
        router.get("https://api.securitytrails.com/v1/domain/example.com/subdomains").mock(
            side_effect=httpx.ConnectError(f"could not reach https://api.shodan.io/dns/domain/example.com?key={CANARY}")
        )
        router.get("https://api.shodan.io/dns/domain/example.com").mock(  # the key travels in this URL
            return_value=httpx.Response(200, json={"subdomains": ["sh"], "data": [], "more": False})
        )
        result = await tools.scan("example.com", max_steps=40, attribution=True)

    surfaces: dict[str, str] = {
        "logs": caplog.text + "\n".join(str(r.args) for r in caplog.records),
        "mcp scan": json.dumps(result),
        "mcp risk": json.dumps(tools.risk()),
        "mcp candidates": json.dumps(tools.list_candidates(min_band="unlikely")),
        "mcp attribution": json.dumps(tools.attribution(min_band="unlikely")),
    }
    store = Store(db)
    report = build_report(store, result["scan_id"])
    assert {"vt.example.com", "sh.example.com"} <= {e["value"] for e in report["entities"]}  # the keyed sources ran
    assert report["sources"]["securitytrails"]["error"] == 1
    generate_keypair(tmp_path / "keys")
    bundle = tmp_path / "proof.scrutator"
    create_bundle(store, result["scan_id"], load_private_key(private_key_path(tmp_path / "keys")), bundle)
    surfaces["audit log"] = json.dumps(store.audit_log(result["scan_id"]))
    store.close()
    surfaces["report"] = render_json(report)
    surfaces["html"] = render_html(report)
    surfaces["database file"] = db.read_bytes().decode("latin-1")
    with zipfile.ZipFile(bundle) as archive:
        for name in archive.namelist():
            surfaces[f"bundle {name}"] = archive.read(name).decode("utf-8")
    surfaces["bundle file"] = bundle.read_bytes().decode("latin-1")
    runner = CliRunner()
    for args in (
        ["sources", "--db", str(db)],
        ["sources", "--db", str(db), "--json"],
        ["risk", "--db", str(db)],
        ["candidates", "--db", str(db), "--min-band", "unlikely"],
        ["attribution", "--db", str(db), "--min-band", "unlikely"],
        ["verify", str(bundle)],
    ):
        outcome = runner.invoke(cli.app, args)
        assert outcome.exit_code == 0, (args, outcome.output)
        surfaces[" ".join(args[:1] + args[3:])] = outcome.output

    assert [name for name, text in surfaces.items() if leaked(text)] == []
    assert "[redacted]" in surfaces["audit log"]  # the error that quoted the URL is there, without the key


def test_the_redaction_filter_rewrites_a_log_record_that_carries_a_key(canary_env, caplog):
    install_log_redaction()
    caplog.set_level(logging.DEBUG)
    logging.getLogger("httpx").info('HTTP Request: %s %s "%s"', "GET", f"https://api.shodan.io/x?key={CANARY}", "200")
    assert not leaked(caplog.text) and "key=[redacted]" in caplog.text


def test_the_mcp_server_keeps_request_urls_out_of_its_stderr_log(canary_env):
    pytest.importorskip("mcp")
    from scrutator.mcp_server import build_server

    build_server(ToolSet("unused.db"))  # the SDK sets up logging here
    assert logging.getLogger("httpx").level >= logging.WARNING  # set on the logger itself, not inherited by luck
