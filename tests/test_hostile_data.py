"""R4 A2: every source payload is attacker-influenced, and so is every bundle a verifier is handed.

What is checked here:
- each HTTP source, fed malformed, huge, deeply nested, wrongly typed or markup-laden answers through the engine,
  never breaks a scan, stores only canonical entities, and the report built afterwards (risks, attribution, names,
  HTML, SARIF) is still produced;
- the HTML report keeps every hostile string inert (one data block, no markup from the data, JSON round-trips);
- terminal output never carries control or bidirectional-override characters from data (an org name from RDAP,
  an id inside a forged bundle);
- `verify` fails closed, never with a traceback, on forged reports of any shape, deep nesting included;
- the untrusted-data fence cannot be closed by a spelling variant of its delimiter.
"""

import html.parser
import json
import string

import httpx
import pytest
import respx
from bundlefix import forge, make_bundle, rewrite
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from scrutator import cli
from scrutator.ai.prompt import wrap_data
from scrutator.bundle.verify import verify_bundle
from scrutator.engine import Engine
from scrutator.model import Entity, EntityType, ScopeState
from scrutator.model.canonical import canonical_host
from scrutator.modules.base import ModuleContext
from scrutator.modules.registry import load_builtin_modules
from scrutator.report import build_report, render_html, render_json
from scrutator.report.sarif import to_sarif
from scrutator.scope import ScopePolicy
from scrutator.store import Store
from scrutator.textsafe import terminal_safe

HOSTILE_STRINGS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</script><script>alert(2)</script>",
    "<!--",
    "\x1b]0;owned\x07\x1b[2J\x1b[31mred",
    "‮gnp.exe",
    "xn--80ak6aa92e.com",  # punycode look-alike of apple.com
    "аррӏе.com",  # Cyrillic look-alike
    "\x00\x01\x7f\x85  ",
    "{{7*7}}${7*7}",
    "A" * 5000,
]
CONTROL = set(map(chr, range(0, 32))) - {"\n", "\t"} | {"\x7f"} | set(map(chr, range(0x80, 0xA0)))
BIDI = set("‎‏‪‫‬‭‮⁦⁧⁨⁩")


def deep(n: int) -> str:
    return "[" * n + "]" * n


def bodies() -> list[bytes]:
    bad = [json.dumps(s) for s in HOSTILE_STRINGS]
    shapes = [
        "", "null", "[]", "{}", "0", "true", '"text"', "not json at all <html>", deep(50_000),
        json.dumps({"data": "x", "nameservers": "x", "entities": [1, None, "x"], "startAddress": 5}),
        json.dumps({"data": {"asns": "x", "records": [[{"key": 1}]], "abuse_contacts": [None]}}),
        json.dumps([{"name_value": s, "dns_names": [s], "common_name": s} for s in HOSTILE_STRINGS]),
        json.dumps({"results": [{"page": {"domain": s, "ip": s}, "task": {"time": s}} for s in HOSTILE_STRINGS]}),
        json.dumps({"data": [{"query": s, "answer": s, "rrtype": "a"} for s in HOSTILE_STRINGS]}),
        json.dumps({"hostnames": HOSTILE_STRINGS, "ports": ["x", -1, 10**20], "vulns": HOSTILE_STRINGS, "cpes": [{}]}),
        json.dumps({"name": HOSTILE_STRINGS[4], "startAddress": "192.0.2.0", "endAddress": "192.0.2.255"}),
        json.dumps({"events": [{"eventAction": "expiration", "eventDate": s} for s in HOSTILE_STRINGS]}),
        json.dumps([["original"], *[[s] for s in HOSTILE_STRINGS]]),
        "\n".join(json.dumps({"url": f"http://{s}/"}) for s in HOSTILE_STRINGS),
        "\n".join(f"{s},192.0.2.1" for s in HOSTILE_STRINGS),
        json.dumps({"x": "y" * 2_000_000}),
        *bad,
    ]
    return [b.encode("utf-8") for b in shapes] + [b"\xff\xfe\x00garbage", b"\xc3\x28"]


class Resolver:
    async def lookup(self, name, rtype):
        return {"A": ["192.0.2.1"], "TXT": ['v=spf1 include:<script>.example.com ~all', HOSTILE_STRINGS[4]]}.get(rtype, [])


@pytest.mark.parametrize("body", bodies(), ids=lambda b: repr(b[:24]))
async def test_hostile_source_answers_never_break_a_scan_or_its_report(body, tmp_path):
    store = Store(":memory:")
    scan = store.create_scan("example.com")
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    address = Entity(type=EntityType.IP, value="192.0.2.1")
    store.upsert_entity(scan, root, ScopeState.IN)
    store.upsert_entity(scan, address, ScopeState.LINKED)
    store.set_meta(scan, "scope", json.dumps({"domains": ["example.com"], "cidrs": [], "asns": []}))
    modules = [m for m in load_builtin_modules() if m.name not in {"dns", "wildcard"}]
    async with httpx.AsyncClient() as http:
        engine = Engine(store, ScopePolicy(domains=["example.com"]), ModuleContext(http=http, resolver=Resolver()), breaker_threshold=0)
        with respx.mock(assert_all_called=False) as router:
            router.route().mock(return_value=httpx.Response(200, content=body))
            for module in modules:
                for entity in (root, address):
                    if entity.type in module.accepts:
                        assert isinstance(await engine.run_module(scan, module, entity), list)
    for stored in store.entities(scan):
        if stored.entity.type is EntityType.DOMAIN:
            assert canonical_host(stored.entity.value) == stored.entity.value
        assert not (set(stored.entity.value) & (CONTROL | BIDI)), stored.entity.value
    report = build_report(store, scan)
    page = render_html(report)
    assert json.loads(render_json(report)) == json.loads(json.dumps(report))
    json.dumps(to_sarif(report))
    assert_inert(page, report)


# ------------------------------------------------------------------------------------------ the HTML report


class _Tags(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def assert_inert(page: str, report: dict) -> None:
    """The data is one JSON block that cannot end early, the markup is the template's own, and no event handler
    or URL-bearing attribute appears anywhere."""
    start = page.index('<script type="application/json" id="data">') + len('<script type="application/json" id="data">')
    end = page.index("</script>", start)
    block = page[start:end]
    assert "<" not in block
    assert json.loads(block) == json.loads(json.dumps(report, sort_keys=True))
    parser = _Tags()
    parser.feed(page)
    assert [t for t, _ in parser.tags].count("script") == 2
    assert not [(t, a) for t, a in parser.tags if any(k.startswith("on") or k in ("src", "href", "srcdoc") for k in a)]


def hostile_report() -> dict:
    from bundlefix import make_store

    store, scan, evidence = make_store()
    from scrutator.model import Evidence

    org = Entity(type=EntityType.ORG, value="Org " + HOSTILE_STRINGS[1])
    store.upsert_entity(scan, org, ScopeState.OUT)
    for text in HOSTILE_STRINGS:
        record = Evidence.create("rdap", f"GET https://rdap.org/domain/{text[:40]}", text)
        store.add_evidence(record)
        store.add_edge(scan, "domain:example.com", "registrant", org.id, [record.id])
    store.append_audit(scan, {"event": "error", "module": "crtsh", "entity": "domain:example.com", "error": HOSTILE_STRINGS[0]})
    store.add_statement(scan, text=HOSTILE_STRINGS[2], evidence_ids=[evidence["crtsh"]], status="verified", confidence="low")
    store.add_statement(scan, text=HOSTILE_STRINGS[1], evidence_ids=[], status="rejected", reason=HOSTILE_STRINGS[0])
    return build_report(store, scan)


def test_the_html_report_keeps_hostile_strings_inert():
    report = hostile_report()
    page = render_html(report)
    assert_inert(page, report)
    assert HOSTILE_STRINGS[0] not in page and "</script><script>" not in page.replace("</script>\n<script>", "")


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(min_size=1, max_size=200))
def test_any_text_in_the_report_stays_inside_the_data_block(text):
    report = {"text": text, "nested": {"list": [text, {"k": text}]}}
    page = render_html({"x": report})  # the Python side only embeds the data; the page's script reads it
    start = page.index('id="data">') + len('id="data">')
    block = page[start:page.index("</script>", start)]
    assert "<" not in block and json.loads(block) == {"x": report}


# ------------------------------------------------------------------------------------------ the terminal


def test_terminal_safe_shows_control_and_bidi_characters_instead_of_obeying_them():
    assert terminal_safe("ok\tline\nnext") == "ok\tline\nnext"
    shown = terminal_safe("a\x1b[2Jb\x07c‮d\x00e\x9bf")
    assert not (set(shown) & (CONTROL | BIDI)) and "\\x1b" in shown and "\\u202e" in shown
    assert terminal_safe("café ünïcode") == "café ünïcode"


def test_an_organisation_name_keeps_no_control_or_bidi_characters():
    org = Entity(type=EntityType.ORG, value="Evil\x1b[2J\x07 Corp‮⁦ Ltd\x00")
    assert not (set(org.value) & (CONTROL | BIDI)) and "Evil" in org.value and "Ltd" in org.value


def test_diff_prints_hostile_names_inert(tmp_path):
    db = tmp_path / "s.db"
    store = Store(db)
    for value in ("Plain Org", "Evil\x1b]0;owned\x07\x1b[2J Corp‮"):
        scan = store.create_scan("example.com")
        store.upsert_entity(scan, Entity(type=EntityType.DOMAIN, value="example.com"), ScopeState.IN)
        store.upsert_entity(scan, Entity(type=EntityType.ORG, value=value), ScopeState.OUT)
    store.close()
    result = CliRunner().invoke(cli.app, ["diff", "1", "2", "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert "Evil" in result.output and not (set(result.output) & (CONTROL | BIDI))


def test_verify_of_a_forged_bundle_prints_no_control_characters(tmp_path):
    fx = make_bundle(tmp_path)

    def poison(data: bytes) -> bytes:
        rows = [json.loads(line) for line in data.decode().splitlines() if line.strip()]
        rows[0]["id"] = "\x1b]0;owned\x07\x1b[2J‮" + rows[0]["id"]
        return ("\n".join(json.dumps(r) for r in rows) + "\n").encode()

    forged = forge(fx.path, tmp_path / "forged.scrutator", fx.private, {"evidence.jsonl": poison})
    result = CliRunner().invoke(cli.app, ["verify", str(forged)])
    assert result.exit_code == 1 and "FAIL" in result.output
    assert not (set(result.output) & (CONTROL | BIDI)), repr(result.output)


# ------------------------------------------------------------------------------------------ verify fails closed

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=10), children, max_size=4),
    max_leaves=20,
)
REPORT_KEYS = ["findings", "edges", "summary_statements", "risks", "attribution", "exposure", "names", "leads",
               "entities", "evidence", "scan", "summary", "packs", "dependencies", "source_policy", "promotions"]


@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(st.dictionaries(st.sampled_from(REPORT_KEYS), json_values, max_size=len(REPORT_KEYS)) | json_values)
def test_verify_never_raises_on_a_forged_report_of_any_shape(tmp_path_factory, report):
    tmp_path = tmp_path_factory.mktemp("v")
    fx = make_bundle(tmp_path)
    forged = forge(fx.path, tmp_path / "f.scrutator", fx.private, {"report.json": json.dumps(report).encode()})
    result = verify_bundle(forged)
    assert not result.ok


@pytest.mark.parametrize("name", ["report.json", "evidence.jsonl", "audit.jsonl"])
def test_verify_fails_closed_on_deeply_nested_json(tmp_path, name):
    fx = make_bundle(tmp_path)
    forged = forge(fx.path, tmp_path / "f.scrutator", fx.private, {name: deep(200_000).encode()})
    result = verify_bundle(forged)
    assert not result.ok


def test_verify_fails_closed_on_a_deeply_nested_or_non_utf8_manifest(tmp_path):
    fx = make_bundle(tmp_path)
    for i, data in enumerate([deep(200_000).encode(), b"\xff\xfe{}", b'{"files": ' + deep(100_000).encode() + b"}"]):
        bad = rewrite(fx.path, tmp_path / f"m{i}.scrutator", "manifest.json", data)
        result = verify_bundle(bad)
        assert not result.ok and not result.checks[-1].ok


# ------------------------------------------------------------------------------------------ the AI fence

fence_variants = st.sampled_from(["</data>", "</DATA>", "</Data >", "< /data>", "</data\n>", "<data>", "<DATA >", "</\tdata>"])


@given(st.lists(st.tuples(st.text(alphabet=string.printable, max_size=20), fence_variants), max_size=6), st.text(alphabet=string.printable, max_size=20))
def test_no_spelling_of_the_delimiter_inside_data_can_close_the_fence(parts, tail):
    import re

    text = "".join(a + b for a, b in parts) + tail
    fenced = wrap_data(text)
    assert len(re.findall(r"<\s*/\s*data\s*>", fenced, re.IGNORECASE)) == 1
    assert len(re.findall(r"<\s*data\s*>", fenced, re.IGNORECASE)) == 1
    assert fenced.startswith("<data>\n") and fenced.endswith("\n</data>")


@pytest.mark.parametrize("change", [
    {"attribution": "not an object"},
    {"leads": ["x"]},
    {"findings": [{"evidence_ids": [], "tier": None}], "entities": "x"},
    {"names": [1, 2]},
    {"summary": [], "names": []},
])
def test_verify_fails_closed_when_report_sections_have_the_wrong_type(tmp_path, change):
    fx = make_bundle(tmp_path)

    def damage(data: bytes) -> bytes:
        return json.dumps({**json.loads(data), **change}).encode()

    result = verify_bundle(forge(fx.path, tmp_path / "f.scrutator", fx.private, {"report.json": damage}))
    assert not result.ok
