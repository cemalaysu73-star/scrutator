import json

import httpx
import pytest
import respx

from scrutator.model import Entity, EntityType, ScopeState
from scrutator.store import Store
from scrutator.watch import make_webhook_notifier, parse_interval, validate_webhook, watch_loop

D = EntityType.DOMAIN


@pytest.mark.parametrize("text, seconds", [("30s", 30), ("5m", 300), ("6h", 21600), ("1d", 86400), (" 2H ", 7200)])
def test_parse_interval(text, seconds):
    assert parse_interval(text) == seconds


@pytest.mark.parametrize("text", ["", "0m", "10", "5x", "-5m", "1.5h", "m5"])
def test_parse_interval_rejects_nonsense(text):
    with pytest.raises(ValueError):
        parse_interval(text)


@pytest.mark.parametrize("url", ["https://hooks.example.test/x", "http://127.0.0.1:9000/hook", "http://localhost/hook"])
def test_webhook_urls_must_be_https_or_loopback(url):
    assert validate_webhook(url) == url


@pytest.mark.parametrize("url", ["http://hooks.example.test/x", "ftp://x/y", "file:///etc/passwd", "not a url", ""])
def test_other_webhook_urls_are_refused(url):
    with pytest.raises(ValueError):
        validate_webhook(url)


def make_runner(store, plan):
    """plan: one list of subdomain labels per run."""
    runs = iter(plan)

    async def run_once():
        sid = store.create_scan("example.com")
        store.upsert_entity(sid, Entity(type=D, value="example.com"), ScopeState.IN)
        for label in next(runs):
            store.upsert_entity(sid, Entity(type=D, value=f"{label}.example.com"), ScopeState.IN)
        return sid

    return run_once


async def test_changes_between_runs_are_notified_and_quiet_runs_are_not():
    store = Store(":memory:")
    sleeps, notices, seen = [], [], []

    async def sleep(seconds):
        sleeps.append(seconds)

    async def notify(seed, scan_id, previous, diff):
        notices.append((seed, scan_id, previous, [e["value"] for e in diff.added_entities]))

    await watch_loop(
        run_once=make_runner(store, [["a"], ["a", "b"], ["a", "b"]]),
        store=store, seed="example.com", interval=3600, max_runs=3, notify=notify, sleep=sleep,
        on_run=lambda sid, prev, diff: seen.append((sid, prev, None if diff is None else diff.empty)),
    )
    assert sleeps == [3600, 3600]
    assert seen == [(1, None, None), (2, 1, False), (3, 2, True)]
    assert notices == [("example.com", 2, 1, ["b.example.com"])]


async def test_a_previous_scan_in_the_database_is_the_baseline():
    store = Store(":memory:")
    first = store.create_scan("example.com")
    store.upsert_entity(first, Entity(type=D, value="example.com"), ScopeState.IN)
    notices = []

    async def notify(seed, scan_id, previous, diff):
        notices.append((previous, [e["value"] for e in diff.added_entities]))

    async def sleep(seconds):
        pass

    await watch_loop(
        run_once=make_runner(store, [["x"]]), store=store, seed="example.com",
        interval=60, max_runs=1, notify=notify, sleep=sleep,
    )
    assert notices == [(first, ["x.example.com"])]


async def test_webhook_payload_is_a_summary_without_raw_evidence():
    store = Store(":memory:")
    runner = make_runner(store, [["a"], ["a", "b"]])
    async with httpx.AsyncClient() as client:
        with respx.mock() as router:
            route = router.post("https://hooks.example.test/x").mock(return_value=httpx.Response(200))
            notify = make_webhook_notifier("https://hooks.example.test/x", client)

            async def sleep(seconds):
                pass

            await watch_loop(run_once=runner, store=store, seed="example.com", interval=60, max_runs=2, notify=notify, sleep=sleep)
    body = json.loads(route.calls.last.request.content)
    assert body["seed"] == "example.com" and body["scan_id"] == 2 and body["previous_scan_id"] == 1
    assert body["counts"]["added_entities"] == 1
    assert body["changes"]["added_entities"][0]["value"] == "b.example.com"
    assert "evidence" not in body and "payload" not in json.dumps(body)


async def test_a_failing_webhook_does_not_stop_the_watch():
    store = Store(":memory:")
    async with httpx.AsyncClient() as client:
        with respx.mock() as router:
            router.post("https://hooks.example.test/x").mock(side_effect=httpx.ConnectError("down"))
            notify = make_webhook_notifier("https://hooks.example.test/x", client)

            async def sleep(seconds):
                pass

            await watch_loop(run_once=make_runner(store, [["a"], ["b"], ["c"]]), store=store, seed="example.com",
                             interval=60, max_runs=3, notify=notify, sleep=sleep)
    assert len(store.scans()) == 3
