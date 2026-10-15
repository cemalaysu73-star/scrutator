from scrutator.store import GENESIS_HASH, Store, chain_hash


def test_meta_round_trip_replace_and_isolation():
    store = Store(":memory:")
    a, b = store.create_scan("a.com"), store.create_scan("b.com")
    assert store.get_meta(a, "scope") is None
    store.set_meta(a, "scope", "one")
    store.set_meta(a, "scope", "two")
    assert store.get_meta(a, "scope") == "two"
    assert store.get_meta(b, "scope") is None


def test_scans_and_latest_scan():
    store = Store(":memory:")
    first = store.create_scan("example.com")
    other = store.create_scan("other.net")
    second = store.create_scan("example.com")
    assert store.latest_scan("example.com") == second
    assert store.latest_scan("other.net") == other
    assert store.latest_scan("nobody.org") is None
    assert [s["id"] for s in store.scans()] == [first, other, second]
    assert store.scans()[0]["seed"] == "example.com"


def test_audit_rows_can_be_verified_independently():
    store = Store(":memory:")
    sid = store.create_scan("x.com")
    store.append_audit(sid, {"event": "ok"})
    store.append_audit(sid, {"event": "ok", "n": 2})
    rows = store.audit_rows(sid)
    assert [r["seq"] for r in rows] == [1, 2]
    previous = GENESIS_HASH
    for row in rows:
        assert row["prev_hash"] == previous
        assert chain_hash(previous, row["record"]) == row["hash"]
        previous = row["hash"]
