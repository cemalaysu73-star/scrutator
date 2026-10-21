"""R7 T5: monitoring that sells. `watch` keeps a baseline per client, turns what is new into severity-ranked alerts
announced once, each with its evidence and a "why this matters" line (AI-reworded only when verified), writes a weekly
digest, and can e-mail it with credentials that come only from the environment and never reach any output."""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from typer.testing import CliRunner

from llmfakes import ScriptedProvider
from scrutator import cli, monitor
from scrutator.ai.runtime import AIRuntime
from scrutator.benchlab.fakes import Router, StatusResolver
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.monitor import Alert, SmtpConfig, current_keys, dedupe, diff_snapshots, explain, render_digest, send_email
from scrutator.scan import run_scan

runner = CliRunner()
CANARY = "s3cr3t-SMTP-canary-77"


def _crt_rows(names):
    now = datetime.now(timezone.utc)
    return [{"id": 2000 + i, "issuer_name": "C=US, O=Example CA", "name_value": n,
             "not_before": (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S"), "not_after": (now + timedelta(days=80)).strftime("%Y-%m-%dT%H:%M:%S")}
            for i, n in enumerate(names)]


ROUNDS = [
    {"crt": ["www.example.com"], "zone": {("www.example.com", "A"): ["1.1.1.1"]}, "ports": {"1.1.1.1": [443]}},
    {"crt": ["www.example.com", "dev.example.com", "shop.example.com"],
     "zone": {("www.example.com", "A"): ["1.1.1.1"], ("dev.example.com", "A"): ["1.1.1.2"],
              ("shop.example.com", "CNAME"): ["shop-demo.azurewebsites.net."], ("shop.example.com", "A"): "NXDOMAIN"},
     "ports": {"1.1.1.1": [443, 3389], "1.1.1.2": [443]}},
]
ROUNDS.append(ROUNDS[1])


@pytest.fixture
def plan(monkeypatch):
    state = {"round": 0}

    @asynccontextmanager
    async def context():
        step = ROUNDS[min(state["round"], len(ROUNDS) - 1)]
        router = Router()
        router.add("crt.sh", "/", httpx.Response(200, json=_crt_rows(step["crt"])))
        router.add("internetdb.shodan.io", r"/(.+)", lambda r: httpx.Response(200, json={"ip": r.url.path[1:], "ports": step["ports"].get(r.url.path[1:], []), "cpes": [], "vulns": [], "hostnames": [], "tags": []}), regex=True)
        async with httpx.AsyncClient(transport=router.transport()) as http:
            yield ModuleContext(http=http, resolver=StatusResolver(step["zone"]))

    real = run_scan

    async def scan(seed, scope, store, ctx, **kwargs):
        modules = [m for m in load_builtin_modules() if m.name in ("crtsh", "dns", "internetdb")]
        return await real(seed, scope, store, ctx, modules=modules, max_steps=500)

    async def next_round(_seconds):
        state["round"] += 1

    monkeypatch.setattr(cli, "open_context", context)
    monkeypatch.setattr(cli, "run_scan", scan)
    monkeypatch.setattr(cli, "_sleep", next_round)
    return state


def test_watch_announces_new_things_once_with_severity_evidence_and_why(tmp_path, plan):
    out = tmp_path / "client-a"
    with respx.mock() as router:
        route = router.post("https://hooks.example.test/x").mock(return_value=httpx.Response(200))
        result = runner.invoke(cli.app, ["watch", "example.com", "--every", "1h", "--max-runs", "3", "--out", str(out),
                                         "--client", "Client A", "--webhook", "https://hooks.example.test/x"])
    assert result.exit_code == 0, result.output
    assert result.output.count("Alerts for Client A") == 1  # run 2 only: run 1 is the baseline, run 3 repeats nothing
    assert "[HIGH  ] CNAME to a claimable service" in result.output  # severity-ranked: the takeover first
    assert "New open port 3389 on 1.1.1.1" in result.output and "New verified name: dev.example.com" in result.output
    assert "why it matters: An alias that points at a resource" in result.output and "evidence: " in result.output
    assert "New certificate" not in result.output  # info, below the default --min-severity low
    state = json.loads((out / "monitor-state.json").read_text(encoding="utf-8"))
    assert any(r["kind"] == "new_cert" for r in state["history"])  # kept, just not announced
    digest = next(out.glob("digest-*-W*.md")).read_text(encoding="utf-8")
    assert "Weekly monitoring digest: Client A" in digest and "## HIGH" in digest and "Evidence:" in digest
    body = json.loads(route.calls[0].request.content)
    assert body["client"] == "Client A" and {a["kind"] for a in body["alerts"]} >= {"new_takeover", "new_service", "new_name"}
    assert all(a["evidence_ids"] for a in body["alerts"]) and "payload" not in json.dumps(body)


def test_min_severity_high_announces_only_the_takeover(tmp_path, plan):
    result = runner.invoke(cli.app, ["watch", "example.com", "--max-runs", "2", "--every", "1h", "--out", str(tmp_path / "w"), "--min-severity", "high"])
    assert result.exit_code == 0, result.output
    assert "[HIGH  ]" in result.output and "[MEDIUM]" not in result.output and "[LOW   ]" not in result.output


def test_a_new_client_folder_is_a_new_baseline(tmp_path, plan):
    plan["round"] = 1
    result = runner.invoke(cli.app, ["watch", "example.com", "--max-runs", "1", "--out", str(tmp_path / "b")])
    assert result.exit_code == 0 and "Alerts for" not in result.output  # nothing is new on a first look


# ------------------------------------------------------------------------------------------- dedupe


def _snap(names=(), risks=()):
    return {"names": {n: ["e" * 64] for n in names}, "certs": {}, "services": {},
            "risks": {fp: {"rule_id": "caa-missing", "severity": "low", "title": "No CAA", "entities": ["example.com"], "explanation": "x", "evidence_ids": ["f" * 64]} for fp in risks}}


def test_a_thing_that_goes_away_and_comes_back_is_announced_again():
    alerted: set = set()
    sequence = [_snap(), _snap(risks=["r1"]), _snap(risks=["r1"]), _snap(), _snap(), _snap(risks=["r1"])]
    announced = []
    previous = None
    for snap in sequence:
        fresh, alerted = dedupe(diff_snapshots(previous, snap), alerted, current_keys(snap))
        announced.append([a.kind for a in fresh])
        previous = snap
    assert announced == [[], ["new_risk"], [], ["resolved_risk"], [], ["new_risk"]]


# ------------------------------------------------------------------------------------------- e-mail


class FakeSMTP:
    sent: list = []

    def __init__(self, host, port, timeout=30, **kwargs):
        self.host, self.port, self.events = host, port, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.events.append("starttls")

    def login(self, user, password):
        self.events.append(("login", user))
        if password != CANARY:
            raise AssertionError("wrong password")

    def send_message(self, message):
        FakeSMTP.sent.append((self.events[:], message))


def test_email_credentials_come_only_from_the_environment():
    with pytest.raises(ValueError, match="SCRUTATOR_SMTP_HOST"):
        SmtpConfig.from_env({})
    config = SmtpConfig.from_env({"SCRUTATOR_SMTP_HOST": "smtp.example.com", "SCRUTATOR_SMTP_FROM": "a@example.com", "SCRUTATOR_SMTP_PASSWORD": CANARY, "SCRUTATOR_SMTP_USER": "a"})
    assert config.tls == "starttls" and config.port == 587 and CANARY not in repr(config)
    assert SmtpConfig.from_env({"SCRUTATOR_SMTP_HOST": "h.example.com", "SCRUTATOR_SMTP_FROM": "a@example.com", "SCRUTATOR_SMTP_PORT": "465"}).tls == "ssl"


def test_a_failing_server_never_shows_the_password():
    config = SmtpConfig("smtp.example.com", 587, "a", CANARY, "a@example.com", "starttls")

    def factory(_config):
        raise OSError(f"login failed for a:{CANARY}")

    problem = send_email(config, ["b@example.com"], "s", "body", smtp_factory=factory)
    assert problem.startswith("e-mail not sent") and CANARY not in problem and "[redacted]" in problem


def test_watch_emails_the_alerts_and_the_password_appears_nowhere(tmp_path, plan, monkeypatch):
    FakeSMTP.sent = []
    monkeypatch.setattr(monitor.smtplib, "SMTP", FakeSMTP)
    for key, value in {"SCRUTATOR_SMTP_HOST": "smtp.example.com", "SCRUTATOR_SMTP_FROM": "watch@example.com",
                       "SCRUTATOR_SMTP_USER": "watch", "SCRUTATOR_SMTP_PASSWORD": CANARY}.items():
        monkeypatch.setenv(key, value)
    out = tmp_path / "w"
    result = runner.invoke(cli.app, ["watch", "example.com", "--max-runs", "2", "--every", "1h", "--out", str(out), "--email-to", "it@example.com"])
    assert result.exit_code == 0, result.output
    assert len(FakeSMTP.sent) == 1
    events, message = FakeSMTP.sent[0]
    assert events[0] == "starttls" and events[1] == ("login", "watch")  # TLS before credentials
    assert message["To"] == "it@example.com" and "new alert(s)" in message["Subject"]
    assert CANARY not in result.output
    for path in out.rglob("*"):
        if path.is_file() and path.suffix in (".json", ".md", ".jsonl"):
            assert CANARY not in path.read_text(encoding="utf-8", errors="replace")


def test_email_without_a_server_in_the_environment_is_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("SCRUTATOR_SMTP_HOST", raising=False)
    result = runner.invoke(cli.app, ["watch", "example.com", "--max-runs", "1", "--out", str(tmp_path / "w"), "--email-to", "it@example.com"])
    assert result.exit_code == 2 and "SCRUTATOR_SMTP_HOST" in result.output


# ------------------------------------------------------------------------------------------- AI "why this matters"


def _alert():
    return Alert("new_service", "svc:1.1.1.1:3389", "medium", "New open port 3389 on 1.1.1.1",
                 "Shodan InternetDB lists port 3389 open on 1.1.1.1, which www.example.com resolve(s) to.", ["a" * 64],
                 monitor.WHY["new_service"], entities=["1.1.1.1", "www.example.com"])


def test_an_invented_why_is_refused_and_the_deterministic_one_kept():
    alert = _alert()
    writer = ScriptedProvider(responder=lambda s, u, schema: {"text": "Port 3389 on 203.0.113.9 is being exploited right now."})
    verifier = ScriptedProvider(responder=lambda s, u, schema: {"supported": True}, model="v")
    asyncio.run(explain(AIRuntime({"writer": writer, "verifier": verifier}), [alert], {}))
    assert alert.why == monitor.WHY["new_service"] and alert.why_source == "deterministic"


def test_a_faithful_why_is_kept_only_when_the_verifier_supports_it():
    plain = "A newly listed open port is a newly reachable service on an address that a name resolves to."
    for supported, expected in ((True, "ai-verified"), (False, "deterministic")):
        alert = _alert()
        writer = ScriptedProvider(responder=lambda s, u, schema: {"text": plain})
        verifier = ScriptedProvider(responder=lambda s, u, schema, ok=supported: {"supported": ok, "reason": "r"}, model="v")
        asyncio.run(explain(AIRuntime({"writer": writer, "verifier": verifier}), [alert], {}))
        assert alert.why_source == expected


def test_the_turkish_digest():
    text = render_digest("Müşteri", [{**_alert().to_dict(), "at": "2026-10-21T00:00:00+00:00", "why": monitor.WHY_TR["new_service"]}], period="2026-W43", lang="tr")
    assert "Haftalık izleme özeti" in text and "Neden önemli" in text and "## MEDIUM" in text
