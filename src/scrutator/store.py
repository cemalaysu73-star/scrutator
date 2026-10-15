import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scrutator.model import Edge, Entity, EntityType, Evidence, ScopeState, StoredEntity

GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seed TEXT NOT NULL,
    started_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
    scan_id INTEGER NOT NULL,
    id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    scope TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    request TEXT NOT NULL,
    payload TEXT NOT NULL,
    collected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS edges (
    scan_id INTEGER NOT NULL,
    src TEXT NOT NULL,
    rel TEXT NOT NULL,
    dst TEXT NOT NULL,
    PRIMARY KEY (scan_id, src, rel, dst)
);
CREATE TABLE IF NOT EXISTS edge_evidence (
    scan_id INTEGER NOT NULL,
    src TEXT NOT NULL,
    rel TEXT NOT NULL,
    dst TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, src, rel, dst, evidence_id)
);
CREATE TABLE IF NOT EXISTS audit (
    scan_id INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (scan_id, seq)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _chain_hash(prev_hash: str, record_json: str) -> str:
    return hashlib.sha256((prev_hash + record_json).encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._db = sqlite3.connect(str(path))
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    # scans
    def create_scan(self, seed: str) -> int:
        with self._db:
            cur = self._db.execute(
                "INSERT INTO scans (seed, started_at) VALUES (?, ?)", (seed, _now())
            )
        return int(cur.lastrowid)

    def get_scan(self, scan_id: int) -> tuple[str, str]:
        row = self._db.execute(
            "SELECT seed, started_at FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"no such scan: {scan_id}")
        return row["seed"], row["started_at"]

    # entities
    def upsert_entity(self, scan_id: int, entity: Entity, state: ScopeState) -> bool:
        """Insert, or promote to a higher scope state. True if anything changed."""
        with self._db:
            row = self._db.execute(
                "SELECT scope FROM entities WHERE scan_id = ? AND id = ?",
                (scan_id, entity.id),
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO entities (scan_id, id, type, value, scope, first_seen)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (scan_id, entity.id, entity.type.value, entity.value, state.value, _now()),
                )
                return True
            if state.rank > ScopeState(row["scope"]).rank:
                self._db.execute(
                    "UPDATE entities SET scope = ? WHERE scan_id = ? AND id = ?",
                    (state.value, scan_id, entity.id),
                )
                return True
            return False

    def scope_state(self, scan_id: int, entity_id: str) -> ScopeState | None:
        row = self._db.execute(
            "SELECT scope FROM entities WHERE scan_id = ? AND id = ?", (scan_id, entity_id)
        ).fetchone()
        return ScopeState(row["scope"]) if row else None

    def entities(self, scan_id: int) -> list[StoredEntity]:
        rows = self._db.execute(
            "SELECT type, value, scope FROM entities WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        return [
            StoredEntity(
                entity=Entity(type=EntityType(r["type"]), value=r["value"]),
                state=ScopeState(r["scope"]),
            )
            for r in rows
        ]

    # evidence and edges
    def add_evidence(self, evidence: Evidence) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO evidence (id, source, request, payload, collected_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (evidence.id, evidence.source, evidence.request, evidence.payload, evidence.collected_at),
            )

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        return Evidence(**dict(row)) if row else None

    def evidence_for_scan(self, scan_id: int) -> list[Evidence]:
        rows = self._db.execute(
            "SELECT DISTINCT e.* FROM evidence e"
            " JOIN edge_evidence ee ON ee.evidence_id = e.id"
            " WHERE ee.scan_id = ? ORDER BY e.id",
            (scan_id,),
        ).fetchall()
        return [Evidence(**dict(r)) for r in rows]

    def add_edge(self, scan_id: int, src: str, rel: str, dst: str, evidence_ids: list[str]) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO edges (scan_id, src, rel, dst) VALUES (?, ?, ?, ?)",
                (scan_id, src, rel, dst),
            )
            self._db.executemany(
                "INSERT OR IGNORE INTO edge_evidence (scan_id, src, rel, dst, evidence_id)"
                " VALUES (?, ?, ?, ?, ?)",
                [(scan_id, src, rel, dst, ev_id) for ev_id in evidence_ids],
            )

    def edges(self, scan_id: int) -> list[Edge]:
        rows = self._db.execute(
            "SELECT src, rel, dst FROM edges WHERE scan_id = ? ORDER BY src, rel, dst", (scan_id,)
        ).fetchall()
        evidence: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        for r in self._db.execute(
            "SELECT src, rel, dst, evidence_id FROM edge_evidence WHERE scan_id = ?"
            " ORDER BY evidence_id",
            (scan_id,),
        ):
            evidence[(r["src"], r["rel"], r["dst"])].append(r["evidence_id"])
        return [
            Edge(
                src=r["src"],
                rel=r["rel"],
                dst=r["dst"],
                evidence_ids=tuple(evidence[(r["src"], r["rel"], r["dst"])]),
            )
            for r in rows
        ]

    # audit log
    def append_audit(self, scan_id: int, record: dict) -> None:
        with self._db:
            last = self._db.execute(
                "SELECT seq, hash FROM audit WHERE scan_id = ? ORDER BY seq DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
            seq, prev = (last["seq"] + 1, last["hash"]) if last else (1, GENESIS_HASH)
            body = json.dumps(record, sort_keys=True)
            self._db.execute(
                "INSERT INTO audit (scan_id, seq, prev_hash, hash, record) VALUES (?, ?, ?, ?, ?)",
                (scan_id, seq, prev, _chain_hash(prev, body), body),
            )

    def audit_log(self, scan_id: int) -> list[dict]:
        rows = self._db.execute(
            "SELECT record FROM audit WHERE scan_id = ? ORDER BY seq", (scan_id,)
        ).fetchall()
        return [json.loads(r["record"]) for r in rows]

    def verify_audit(self, scan_id: int) -> bool:
        prev = GENESIS_HASH
        expected_seq = 1
        for r in self._db.execute(
            "SELECT seq, prev_hash, hash, record FROM audit WHERE scan_id = ? ORDER BY seq",
            (scan_id,),
        ):
            if r["seq"] != expected_seq or r["prev_hash"] != prev:
                return False
            if _chain_hash(prev, r["record"]) != r["hash"]:
                return False
            prev = r["hash"]
            expected_seq += 1
        return True
