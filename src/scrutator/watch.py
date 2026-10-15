import asyncio
import re
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from scrutator.ai.net import is_loopback
from scrutator.diff import Diff, diff_reports
from scrutator.report import build_report
from scrutator.store import Store

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

Notifier = Callable[[str, int, int | None, Diff], Awaitable[None]]


def parse_interval(text: str) -> float:
    match = re.fullmatch(r"(\d+)([smhd])", text.strip().lower())
    if not match or int(match.group(1)) == 0:
        raise ValueError(f"interval must look like 30s, 15m, 6h or 1d, not {text!r}")
    return float(int(match.group(1)) * _UNITS[match.group(2)])


def validate_webhook(url: str) -> str:
    """Webhooks carry scan summaries, so they must be HTTPS or loopback."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ValueError(f"not a valid webhook url: {url!r}") from exc
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname and is_loopback(url):
        return url
    raise ValueError("webhook must be an https URL (plain http is allowed only for localhost)")


def make_webhook_notifier(url: str, client: httpx.AsyncClient) -> Notifier:
    validate_webhook(url)

    async def notify(seed: str, scan_id: int, previous: int | None, diff: Diff) -> None:
        changes = diff.to_dict()
        payload = {
            "tool": "scrutator",
            "seed": seed,
            "scan_id": scan_id,
            "previous_scan_id": previous,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "counts": {k: len(v) for k, v in changes.items() if isinstance(v, list)},
            "changes": {k: v for k, v in changes.items() if isinstance(v, list)},
        }
        try:
            await client.post(url, json=payload, timeout=15.0)
        except httpx.HTTPError:
            pass  # a webhook outage must not stop the watch; the diff is still on disk

    return notify


async def watch_loop(
    *,
    run_once: Callable[[], Awaitable[int]],
    store: Store,
    seed: str,
    interval: float,
    max_runs: int = 0,
    notify: Notifier | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_run: Callable[[int, int | None, Diff | None], None] | None = None,
) -> None:
    """Run a scan, diff it against the previous one for the same seed, notify when something
    changed, wait, repeat. `max_runs` of 0 means forever."""
    previous = store.latest_scan(seed)
    runs = 0
    while True:
        scan_id = await run_once()
        runs += 1
        diff = None
        if previous is not None and previous != scan_id:
            diff = diff_reports(build_report(store, previous), build_report(store, scan_id))
        if on_run is not None:
            on_run(scan_id, previous, diff)
        if diff is not None and not diff.empty and notify is not None:
            await notify(seed, scan_id, previous, diff)
        previous = scan_id
        if max_runs and runs >= max_runs:
            return
        await sleep(interval)
