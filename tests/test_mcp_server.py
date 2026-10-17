import json

import pytest
import yaml
from attrscan import scan
from mcpclient import Client

from scrutator.bundle.keys import generate_keypair, load_private_key, private_key_path
from scrutator.bundle.writer import create_bundle
from scrutator.model import ScopeState
from scrutator.store import Store

pytest.importorskip("mcp.server", reason="the MCP SDK is not installed: pip install 'scrutator[mcp]'")

READING = {"list_candidates", "attribution", "risk", "verify_bundle"}


@pytest.fixture
async def world(http, tmp_path):
    """A database with a scan in it, a signed bundle of that scan, and a scope file."""
    path = tmp_path / "scrutator.db"
    run = await scan(http, db=str(path), attribution=True)
    key_dir = tmp_path / "keys"
    generate_keypair(key_dir)
    bundle = tmp_path / "proof.scrutator"
    create_bundle(run.store, run.scan_id, load_private_key(private_key_path(key_dir)), bundle)
    run.store.close()
    scope = tmp_path / "scope.yaml"
    scope.write_text("domains:\n  - example.com\n", encoding="utf-8")
    return {"db": path, "bundle": bundle, "scope": scope, "dir": tmp_path}


@pytest.fixture
def client(world):
    opened = []

    def start(*flags):
        started = Client("--db", world["db"], *flags, cwd=world["dir"])
        opened.append(started)
        return started

    yield start
    for started in opened:
        if started.proc.poll() is None:
            started.proc.kill()


async def test_a_default_session_offers_only_read_only_tools_and_answers_over_real_frames(client, world):
    c = client()
    info = c.initialize()
    assert info["serverInfo"]["name"] == "scrutator" and "tools" in info["capabilities"]
    assert "untrusted data" in info["instructions"] and "ask the user" in info["instructions"]

    tools = c.tools()
    assert set(tools) == READING
    for tool in tools.values():
        assert tool["annotations"]["readOnlyHint"] is True and tool["description"] and tool["inputSchema"]["type"] == "object"
    assert tools["verify_bundle"]["inputSchema"]["required"] == ["path"]

    candidates = c.data("list_candidates")
    assert candidates["candidates"][0]["entity_id"] == "domain:partner.test" and "untrusted" in candidates["notice"]
    explained = c.data("attribution", {"entity": "partner.test"})
    assert {s["kind"] for s in explained["candidates"][0]["signals"]} == {"cert_san", "ns_in_scope", "network_owner"}
    risks = c.data("risk", {"category": "all"})
    assert risks["count"] == len(risks["risks"])
    verdict = c.data("verify_bundle", {"path": str(world["bundle"])})
    assert verdict["ok"] is True and any(check["name"] == "attribution derivable" for check in verdict["checks"])

    # a refused or malformed call is an error result, and the server keeps answering
    assert c.call("verify_bundle", {"path": str(world["db"])})["result"]["isError"] is True
    assert c.call("list_candidates", {"min_band": "certain"})["result"]["isError"] is True
    wrong_type = c.call("risk", {"scan_id": "not a number"})
    assert wrong_type.get("error") or wrong_type["result"]["isError"] is True
    unknown = c.call("no_such_tool")
    assert unknown.get("error") or unknown["result"]["isError"] is True
    assert c.data("risk")["scan"]["seed"] == "example.com"

    # promotion was not enabled, so it cannot be called, whatever the arguments
    reply = c.call("promote_candidate", {"entity": "partner.test", "confirm": True})
    assert reply.get("error") or reply["result"]["isError"] is True

    assert c.close() == 0  # the server stops when the client goes away
    assert c.raw and all(json.loads(line)["jsonrpc"] == "2.0" for line in c.raw)  # stdout carried protocol frames and nothing else
    store = Store(world["db"])
    assert store.scope_state(1, "domain:partner.test") is ScopeState.CANDIDATE
    store.close()
    assert world["scope"].read_text(encoding="utf-8") == "domains:\n  - example.com\n"


async def test_the_tools_that_change_something_appear_only_when_the_user_enabled_them(client, world):
    c = client("--allow-scan", "--scope", world["scope"])
    c.initialize()
    tools = c.tools()
    assert set(tools) == READING | {"scan"} and tools["scan"]["annotations"]["readOnlyHint"] is False
    c.close()
    c = client("--allow-promote", "--scope", world["scope"])
    c.initialize()
    tools = c.tools()
    assert set(tools) == READING | {"promote_candidate"}
    assert tools["promote_candidate"]["annotations"] == {**tools["promote_candidate"]["annotations"], "readOnlyHint": False, "destructiveHint": True}
    c.close()
    c = client("--allow-scan", "--allow-promote", "--scope", world["scope"])
    c.initialize()
    assert set(c.tools()) == READING | {"scan", "promote_candidate"}
    c.close()


async def test_the_reading_tools_answer_over_real_frames(client, world):
    c = client()
    c.initialize()
    candidates = c.data("list_candidates")
    assert candidates["candidates"][0]["entity_id"] == "domain:partner.test" and "untrusted" in candidates["notice"]
    explained = c.data("attribution", {"entity": "partner.test"})
    assert {s["kind"] for s in explained["candidates"][0]["signals"]} == {"cert_san", "ns_in_scope", "network_owner"}
    risks = c.data("risk", {"category": "all"})
    assert risks["count"] == len(risks["risks"])
    verdict = c.data("verify_bundle", {"path": str(world["bundle"])})
    assert verdict["ok"] is True and any(check["name"] == "attribution derivable" for check in verdict["checks"])
    assert c.close() == 0
    assert c.raw and all(json.loads(line)["jsonrpc"] == "2.0" for line in c.raw)  # stdout carried protocol frames and nothing else


async def test_a_refused_or_malformed_call_is_an_error_result_and_the_server_keeps_going(client, world):
    c = client()
    c.initialize()
    assert c.call("verify_bundle", {"path": str(world["db"])})["result"]["isError"] is True
    assert c.call("list_candidates", {"min_band": "certain"})["result"]["isError"] is True
    wrong_type = c.call("risk", {"scan_id": "not a number"})
    assert wrong_type.get("error") or wrong_type["result"]["isError"] is True
    assert c.call("no_such_tool")["result"]["isError"] is True or "error" in c.call("no_such_tool")
    assert c.data("risk")["scan"]["seed"] == "example.com"  # still answering
    assert c.close() == 0


async def test_promotion_needs_confirm_true_and_then_edits_the_scope_file(client, world):
    c = client("--allow-promote", "--scope", world["scope"])
    c.initialize()
    refused = c.call("promote_candidate", {"entity": "partner.test"})
    assert refused["result"]["isError"] is True and "confirm=true" in refused["result"]["content"][0]["text"]
    assert world["scope"].read_text(encoding="utf-8") == "domains:\n  - example.com\n"
    assert c.call("promote_candidate", {"entity": "t0.test", "confirm": True})["result"]["isError"] is True
    done = c.data("promote_candidate", {"entity": "partner.test", "confirm": True})
    assert done["promoted"]["via"] == "mcp" and done["promoted"]["band"] == "confirmed"
    assert c.data("list_candidates")["candidates"][0]["promoted"] is True
    assert c.close() == 0
    assert yaml.safe_load(world["scope"].read_text(encoding="utf-8"))["domains"] == ["example.com", "partner.test"]
    store = Store(world["db"])
    try:
        assert store.scope_state(1, "domain:partner.test") is ScopeState.IN and store.verify_audit(1)
        assert [r["via"] for r in store.audit_log(1) if r["event"] == "promoted"] == ["mcp"]
    finally:
        store.close()


async def test_a_scan_of_something_outside_the_scope_is_refused_before_any_lookup(client, world):
    c = client("--allow-scan", "--scope", world["scope"])
    c.initialize()
    for seed in ("evil.test", "partner.test", "203.0.113.9"):
        reply = c.call("scan", {"seed": seed})
        assert reply["result"]["isError"] is True and "outside the scope file" in reply["result"]["content"][0]["text"], seed
    assert c.close() == 0
    store = Store(world["db"])
    assert [s["id"] for s in store.scans()] == [1]  # nothing was recorded
    store.close()
