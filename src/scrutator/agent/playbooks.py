"""Which playbooks to offer the planner, decided from the graph and nothing else.

`situation` reads the scan's entities and relations and names the situations that hold (see
packs/schema.py for the list). `retrieve` returns the playbooks whose `when` situations all hold,
the most specific first. Retrieval is a pure function of the graph and the pack data, so the same
scan state always offers the same playbooks.
"""

from collections.abc import Sequence

from scrutator.model import ScopeState
from scrutator.packs.schema import PlaybookEntry
from scrutator.store import Store

MAX_OFFERED = 3


def situation(store: Store, scan_id: int) -> frozenset[str]:
    states = {s.entity.id: (s.entity, s.state) for s in store.entities(scan_id)}
    edges = store.edges(scan_id)
    tags: set[str] = set()

    def inside(entity_id: str) -> bool:
        return entity_id in states and states[entity_id][1] is ScopeState.IN

    def outside(entity_id: str) -> bool:
        return entity_id in states and states[entity_id][1] is ScopeState.OUT

    for edge in edges:
        if not inside(edge.src):
            continue
        if edge.rel == "cname_to" and outside(edge.dst):
            tags.add("cname_out")
        elif edge.rel == "related_host" and outside(edge.dst):
            tags.add("san_cohabitants")
        elif edge.rel == "mx":
            tags.add("mail")
        elif edge.rel == "ns":
            tags.add("delegated")
        elif edge.rel == "spf_include":
            tags.add("spf_includes")
    placed = {edge.src for edge in edges if edge.rel == "announced_by"}
    if any(entity.type.value == "ip" and state is ScopeState.LINKED and entity.id not in placed for entity, state in states.values()):
        tags.add("ip_without_network")
    if any(state is ScopeState.CANDIDATE for _, state in states.values()):
        tags.add("candidates")
    return frozenset(tags)


def retrieve(playbooks: Sequence[PlaybookEntry], tags: frozenset[str], *, limit: int = MAX_OFFERED) -> list[PlaybookEntry]:
    """Playbooks whose situations all hold, those naming more situations first, then by id."""
    fitting = [p for p in playbooks if set(p.when) <= tags]
    return sorted(fitting, key=lambda p: (-len(p.when), p.id))[: max(0, limit)]


def render(playbooks: Sequence[PlaybookEntry]) -> str:
    """The guidance as plain lines for the planner's prompt."""
    return "\n".join(f"- {p.title}: " + " ".join(p.steps) + (f" (lookups: {', '.join(p.prefer)})" if p.prefer else "") for p in playbooks)
