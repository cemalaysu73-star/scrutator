from dataclasses import asdict, dataclass, field


@dataclass
class Diff:
    added_entities: list[dict] = field(default_factory=list)
    removed_entities: list[dict] = field(default_factory=list)
    changed_entities: list[dict] = field(default_factory=list)
    added_edges: list[dict] = field(default_factory=list)
    removed_edges: list[dict] = field(default_factory=list)
    changed_findings: list[dict] = field(default_factory=list)
    source_changes: list[dict] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not any(
            (
                self.added_entities,
                self.removed_entities,
                self.changed_entities,
                self.added_edges,
                self.removed_edges,
                self.changed_findings,
                self.source_changes,
            )
        )

    def to_dict(self) -> dict:
        return {**asdict(self), "empty": self.empty}


def _edge_key(edge: dict) -> tuple[str, str, str]:
    return edge["src"], edge["rel"], edge["dst"]


def diff_reports(old: dict, new: dict) -> Diff:
    """What changed between two reports: entities, relations, finding confidence, and how
    well each source answered."""
    old_entities = {e["id"]: e for e in old["entities"]}
    new_entities = {e["id"]: e for e in new["entities"]}
    old_edges = {_edge_key(e): e for e in old["edges"]}
    new_edges = {_edge_key(e): e for e in new["edges"]}
    old_findings = {f["claim"]: f["confidence"] for f in old["findings"]}
    new_findings = {f["claim"]: f["confidence"] for f in new["findings"]}
    old_sources, new_sources = old.get("sources", {}), new.get("sources", {})

    diff = Diff()
    diff.added_entities = [new_entities[i] for i in sorted(new_entities.keys() - old_entities.keys())]
    diff.removed_entities = [old_entities[i] for i in sorted(old_entities.keys() - new_entities.keys())]
    diff.changed_entities = [
        {"id": i, "value": new_entities[i]["value"], "from": old_entities[i]["state"], "to": new_entities[i]["state"]}
        for i in sorted(old_entities.keys() & new_entities.keys())
        if old_entities[i]["state"] != new_entities[i]["state"]
    ]
    diff.added_edges = [new_edges[k] for k in sorted(new_edges.keys() - old_edges.keys())]
    diff.removed_edges = [old_edges[k] for k in sorted(old_edges.keys() - new_edges.keys())]
    diff.changed_findings = [
        {"claim": claim, "from": old_findings[claim], "to": new_findings[claim]}
        for claim in sorted(old_findings.keys() & new_findings.keys())
        if old_findings[claim] != new_findings[claim]
    ]
    for source in sorted(old_sources.keys() | new_sources.keys()):
        before = old_sources.get(source, {}).get("error", 0)
        after = new_sources.get(source, {}).get("error", 0)
        if before != after:
            diff.source_changes.append({"source": source, "from_errors": before, "to_errors": after})
    return diff


def render_diff(diff: Diff, old_label: str, new_label: str) -> str:
    lines = [f"{old_label} -> {new_label}"]
    if diff.empty:
        return "\n".join(lines + ["No changes."])
    for e in diff.added_entities:
        lines.append(f"+ entity {e['type']} {e['value']} ({e['state']})")
    for e in diff.removed_entities:
        lines.append(f"- entity {e['type']} {e['value']} ({e['state']})")
    for e in diff.changed_entities:
        lines.append(f"~ entity {e['value']}: scope {e['from']} -> {e['to']}")
    for e in diff.added_edges:
        lines.append(f"+ relation {e['src']} {e['rel']} {e['dst']}")
    for e in diff.removed_edges:
        lines.append(f"- relation {e['src']} {e['rel']} {e['dst']}")
    for f in diff.changed_findings:
        lines.append(f"~ finding {f['claim']}: confidence {f['from']} -> {f['to']}")
    for s in diff.source_changes:
        lines.append(f"~ source {s['source']}: failed runs {s['from_errors']} -> {s['to_errors']}")
    return "\n".join(lines)
