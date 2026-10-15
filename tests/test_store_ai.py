import pytest

from scrutator.store import Store


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def test_egress_is_recorded_in_order(store):
    sid = store.create_scan("example.com")
    store.record_egress(sid, role="planner", provider="anthropic", model="m", host="api.anthropic.com", bytes_sent=120, payload_sha256="a" * 64, redacted=True)
    store.record_egress(sid, role="verifier", provider="anthropic", model="m", host="api.anthropic.com", bytes_sent=80, payload_sha256="b" * 64, redacted=False)
    log = store.egress_log(sid)
    assert [(e["role"], e["bytes_sent"], e["redacted"]) for e in log] == [("planner", 120, True), ("verifier", 80, False)]
    assert log[0]["payload_sha256"] == "a" * 64
    assert store.egress_log(store.create_scan("other.com")) == []


def test_hypotheses_can_be_added_and_settled(store):
    sid = store.create_scan("example.com")
    hid = store.add_hypothesis(sid, "mail is hosted by a third party")
    assert store.hypotheses(sid) == [{"id": hid, "text": "mail is hosted by a third party", "status": "open", "evidence_ids": []}]
    store.settle_hypothesis(hid, "confirmed", ["e2", "e1"])
    (h,) = store.hypotheses(sid)
    assert h["status"] == "confirmed" and h["evidence_ids"] == ["e1", "e2"]


def test_statements_are_stored_with_status(store):
    sid = store.create_scan("example.com")
    store.add_statement(sid, text="two subdomains exist", evidence_ids=["e1"], status="verified", confidence="medium")
    store.add_statement(sid, text="a hidden datacentre", evidence_ids=[], status="rejected", reason="unknown finding F99")
    assert [s["text"] for s in store.statements(sid)] == ["two subdomains exist", "a hidden datacentre"]
    (verified,) = store.statements(sid, status="verified")
    assert verified["confidence"] == "medium" and verified["evidence_ids"] == ["e1"]
    (rejected,) = store.statements(sid, status="rejected")
    assert rejected["reason"] == "unknown finding F99" and rejected["confidence"] is None
