from collections import Counter

from scrutator.store import Store


def graph_summary(store: Store, scan_id: int) -> str:
    """A few lines of counts, small enough for a local model's context."""
    entities = store.entities(scan_id)
    by_type = Counter(s.entity.type.value for s in entities)
    by_scope = Counter(s.state.value for s in entities)
    return "\n".join(
        [
            "entities: " + ", ".join(f"{k}={v}" for k, v in sorted(by_type.items())),
            "scope: " + ", ".join(f"{k}={v}" for k, v in sorted(by_scope.items())),
            f"relations: {len(store.edges(scan_id))}",
        ]
    )
