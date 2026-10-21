"""Asking once per network: addresses that are likely in one network take turns, so the first answer can cover the rest.

A site on a CDN has dozens of addresses in a handful of networks. The registration and routing services answer about a
whole network (a range, a prefix), so after the first address of a network has been asked about, the others rest on that
record. Addresses near each other (a "lane": the same /16, or /32 for IPv6) therefore go one at a time, while addresses
in different lanes go in parallel.

Taking turns only pays while answers name a network. When an answer names none (a service with no data for that block),
waiting in line saves nothing, so the rest of that lane is asked in parallel.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


def lane(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[int, int]:
    return (address.version, int(address) >> (16 if address.version == 4 else 96))


async def once_per_network(
    cache: dict,
    key: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    covered: Callable[[], T | None],
    ask: Callable[[], Awaitable[T]],
    learned: Callable[[], int],
) -> T:
    """`covered()` gives the answer for the address from what is already known (None if nothing covers it); `ask()`
    asks the service; `learned()` counts the networks known so far (to tell whether an answer named one)."""
    lanes: dict = cache.setdefault(f"{key}-lanes", {})
    here = lane(address)
    while True:
        hit = covered()
        if hit is not None:
            return hit
        state = lanes.get(here)
        if state == "open":
            return await ask()  # answers in this lane name no network: no reason to wait
        if isinstance(state, asyncio.Future) and not state.done():
            await asyncio.shield(state)
            continue
        turn = asyncio.get_running_loop().create_future()
        lanes[here] = turn
        before = learned()
        try:
            return await ask()
        finally:
            if learned() == before:
                lanes[here] = "open"
            turn.set_result(None)
