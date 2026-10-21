import hashlib
import json
import sqlite3
from collections import defaultdict
from contextlib import contextmanager
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
CREATE TABLE IF NOT EXISTS scan_meta (
    scan_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (scan_id, key)
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
CREATE TABLE IF NOT EXISTS scan_evidence (
    scan_id INTEGER NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS audit (
    scan_id INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (scan_id, seq)
);
CREATE TABLE IF NOT EXISTS egress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    at TEXT NOT NULL,
    role TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    host TEXT NOT NULL,
    bytes_sent INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    redacted INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_ids TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    claim TEXT NOT NULL,
    entity_ids TEXT NOT NULL,
    evidence_ids TEXT NOT NULL,
    check_text TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS statements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    evidence_ids TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    confidence TEXT
);
"""


BUSY_TIMEOUT_S = 30.0


class StoreError(Exception):
    """The database cannot be used: not a database, damaged, locked by another process, or not writable."""


def describe_db_error(path, exc: Exception) -> str:
    text = str(exc)
    lowered = text.lower()
    if "locked" in lowered or "busy" in lowered:
        hint = "another process (a running scan, watch or MCP server) holds it; wait for it to finish or use another --db"
    elif "not a database" in lowered or "malformed" in lowered or "corrupt" in lowered:
        hint = "the file is not a Scrutator database or is damaged; point --db at another file and keep this one for inspection"
    elif "readonly" in lowered or "unable to open" in lowered:
        hint = "the file or its directory cannot be written or opened"
    else:
        hint = "SQLite refused the operation"
    return f"database {path}: {text} ({hint})"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def chain_hash(prev_hash: str, record_json: str) -> str:
    return hashlib.sha256((prev_hash + record_json).encode()).hexdigest()


class Store:
    last_path: str | None = None  # the database most recently opened in this process, for error messages

    def __init__(self, path: str | Path = ":memory:", *, timeout: float = BUSY_TIMEOUT_S) -> None:
        Store.last_path = str(path)  # named in the error message of a database that fails later (damaged pages)
        # Two scans (or a scan and an MCP server) may share one database: a writer waits up to `timeout` seconds
        # for the other one's short transaction instead of failing at once. A file that is not a database, or one
        # locked for longer, is a StoreError that names the file and says what to do.
        try:
            self._db = sqlite3.connect(str(path), timeout=timeout)
            self._db.row_factory = sqlite3.Row
            self._db.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise StoreError(describe_db_error(path, exc)) from exc
        self._open_batches = 0

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def _write(self):
        """One write is one transaction, unless a batch is open: then the batch commits for all of them."""
        if self._open_batches:
            yield
        else:
            with self._db:
                yield

    @contextmanager
    def batch(self):
        """Write many records in one transaction. Every commit stalls the event loop (the store is used from
        its thread), so a lookup's results are written together: one commit instead of one per record. Batches
        nest; an exception rolls the outermost one back. Reads inside a batch see its writes."""
        if self._open_batches:
            self._open_batches += 1
            try:
                yield
            finally:
                self._open_batches -= 1
            return
        self._open_batches = 1
        try:
            with self._db:
                yield
        finally:
            self._open_batches = 0

    # scans
    def create_scan(self, seed: str) -> int:
        with self._write():
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

    def scans(self) -> list[dict]:
        rows = self._db.execute("SELECT id, seed, started_at FROM scans ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def latest_scan(self, seed: str) -> int | None:
        row = self._db.execute(
            "SELECT id FROM scans WHERE seed = ? ORDER BY id DESC LIMIT 1", (seed,)
        ).fetchone()
        return int(row["id"]) if row else None

    def set_meta(self, scan_id: int, key: str, value: str) -> None:
        with self._write():
            self._db.execute(
                "INSERT OR REPLACE INTO scan_meta (scan_id, key, value) VALUES (?, ?, ?)",
                (scan_id, key, value),
            )

    def get_meta(self, scan_id: int, key: str) -> str | None:
        row = self._db.execute(
            "SELECT value FROM scan_meta WHERE scan_id = ? AND key = ?", (scan_id, key)
        ).fetchone()
        return row["value"] if row else None

    # entities
    def upsert_entity(self, scan_id: int, entity: Entity, state: ScopeState) -> bool:
        """Insert, or promote to a higher scope state. True if anything changed."""
        with self._write():
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

    def entity_count(self, scan_id: int) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM entities WHERE scan_id = ?", (scan_id,)).fetchone()[0])

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
        with self._write():
            self._db.execute(
                "INSERT OR IGNORE INTO evidence (id, source, request, payload, collected_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (evidence.id, evidence.source, evidence.request, evidence.payload, evidence.collected_at),
            )

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        return Evidence(**dict(row)) if row else None

    def recent_evidence(self, source: str, request_prefix: str, since: str) -> list[Evidence]:
        """Evidence of `source` from any scan in this database whose request starts with `request_prefix` and that was
        collected at or after `since` (ISO 8601, UTC), oldest first. For answers worth reusing across scans (the
        registration of a network): the record is content-addressed, so reusing it cites exactly what was received."""
        rows = self._db.execute(
            "SELECT * FROM evidence WHERE source = ? AND substr(request, 1, ?) = ? AND collected_at >= ?"
            " ORDER BY collected_at, id",
            (source, len(request_prefix), request_prefix, since),
        ).fetchall()
        return [Evidence(**dict(r)) for r in rows]

    def add_scan_evidence(self, scan_id: int, evidence_id: str) -> None:
        """Attach evidence to a scan without attaching it to a relation (see modules.base.Fact)."""
        with self._write():
            self._db.execute(
                "INSERT OR IGNORE INTO scan_evidence (scan_id, evidence_id) VALUES (?, ?)",
                (scan_id, evidence_id),
            )

    def evidence_for_scan(self, scan_id: int) -> list[Evidence]:
        """Every evidence record the scan holds: cited by a relation, or attached as a fact."""
        rows = self._db.execute(
            "SELECT e.* FROM evidence e WHERE e.id IN ("
            " SELECT evidence_id FROM edge_evidence WHERE scan_id = ?1"
            " UNION SELECT evidence_id FROM scan_evidence WHERE scan_id = ?1)"
            " ORDER BY e.id",
            (scan_id,),
        ).fetchall()
        return [Evidence(**dict(r)) for r in rows]

    def add_edge(self, scan_id: int, src: str, rel: str, dst: str, evidence_ids: list[str]) -> None:
        with self._write():
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
        with self._write():
            last = self._db.execute(
                "SELECT seq, hash FROM audit WHERE scan_id = ? ORDER BY seq DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
            seq, prev = (last["seq"] + 1, last["hash"]) if last else (1, GENESIS_HASH)
            body = json.dumps(record, sort_keys=True)
            self._db.execute(
                "INSERT INTO audit (scan_id, seq, prev_hash, hash, record) VALUES (?, ?, ?, ?, ?)",
                (scan_id, seq, prev, chain_hash(prev, body), body),
            )

    def audit_log(self, scan_id: int) -> list[dict]:
        rows = self._db.execute(
            "SELECT record FROM audit WHERE scan_id = ? ORDER BY seq", (scan_id,)
        ).fetchall()
        return [json.loads(r["record"]) for r in rows]

    def audit_rows(self, scan_id: int) -> list[dict]:
        """The raw chain: seq, prev_hash, hash and the record exactly as hashed."""
        rows = self._db.execute(
            "SELECT seq, prev_hash, hash, record FROM audit WHERE scan_id = ? ORDER BY seq",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def verify_audit(self, scan_id: int) -> bool:
        prev = GENESIS_HASH
        expected_seq = 1
        for r in self._db.execute(
            "SELECT seq, prev_hash, hash, record FROM audit WHERE scan_id = ? ORDER BY seq",
            (scan_id,),
        ):
            if r["seq"] != expected_seq or r["prev_hash"] != prev:
                return False
            if chain_hash(prev, r["record"]) != r["hash"]:
                return False
            prev = r["hash"]
            expected_seq += 1
        return True

    # AI egress log
    def record_egress(
        self,
        scan_id: int,
        *,
        role: str,
        provider: str,
        model: str,
        host: str,
        bytes_sent: int,
        payload_sha256: str,
        redacted: bool,
    ) -> None:
        with self._write():
            self._db.execute(
                "INSERT INTO egress (scan_id, at, role, provider, model, host, bytes_sent,"
                " payload_sha256, redacted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, _now(), role, provider, model, host, bytes_sent, payload_sha256, int(redacted)),
            )

    def egress_log(self, scan_id: int) -> list[dict]:
        rows = self._db.execute(
            "SELECT at, role, provider, model, host, bytes_sent, payload_sha256, redacted"
            " FROM egress WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return [{**dict(r), "redacted": bool(r["redacted"])} for r in rows]

    # agent hypotheses
    def add_hypothesis(self, scan_id: int, text: str) -> int:
        with self._write():
            cur = self._db.execute(
                "INSERT INTO hypotheses (scan_id, text, status, evidence_ids) VALUES (?, ?, 'open', '[]')",
                (scan_id, text),
            )
        return int(cur.lastrowid)

    def settle_hypothesis(self, hypothesis_id: int, status: str, evidence_ids: list[str]) -> None:
        with self._write():
            self._db.execute(
                "UPDATE hypotheses SET status = ?, evidence_ids = ? WHERE id = ?",
                (status, json.dumps(sorted(evidence_ids)), hypothesis_id),
            )

    def hypotheses(self, scan_id: int) -> list[dict]:
        rows = self._db.execute(
            "SELECT id, text, status, evidence_ids FROM hypotheses WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return [
            {"id": r["id"], "text": r["text"], "status": r["status"], "evidence_ids": json.loads(r["evidence_ids"])}
            for r in rows
        ]

    # summary statements (writer output after verification)
    def add_statement(
        self,
        scan_id: int,
        *,
        text: str,
        evidence_ids: list[str],
        status: str,
        reason: str = "",
        confidence: str | None = None,
    ) -> None:
        with self._write():
            self._db.execute(
                "INSERT INTO statements (scan_id, text, evidence_ids, status, reason, confidence)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, text, json.dumps(sorted(evidence_ids)), status, reason, confidence),
            )

    def statements(self, scan_id: int, status: str | None = None) -> list[dict]:
        query = "SELECT text, evidence_ids, status, reason, confidence FROM statements WHERE scan_id = ?"
        params: tuple = (scan_id,)
        if status is not None:
            query += " AND status = ?"
            params = (scan_id, status)
        rows = self._db.execute(query + " ORDER BY id", params).fetchall()
        return [
            {
                "text": r["text"],
                "evidence_ids": json.loads(r["evidence_ids"]),
                "status": r["status"],
                "reason": r["reason"],
                "confidence": r["confidence"],
            }
            for r in rows
        ]

    # AI leads and pre-mortems (after verification)
    def add_lead(
        self,
        scan_id: int,
        *,
        kind: str,
        claim: str,
        entity_ids: list[str],
        evidence_ids: list[str],
        status: str,
        check: str = "",
        reason: str = "",
    ) -> None:
        with self._write():
            self._db.execute(
                "INSERT INTO leads (scan_id, kind, claim, entity_ids, evidence_ids, check_text, status, reason)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, kind, claim, json.dumps(sorted(entity_ids)), json.dumps(sorted(evidence_ids)), check, status, reason),
            )

    def leads(self, scan_id: int, status: str | None = None) -> list[dict]:
        query = "SELECT kind, claim, entity_ids, evidence_ids, check_text, status, reason FROM leads WHERE scan_id = ?"
        params: tuple = (scan_id,)
        if status is not None:
            query += " AND status = ?"
            params = (scan_id, status)
        rows = self._db.execute(query + " ORDER BY id", params).fetchall()
        return [
            {
                "kind": r["kind"],
                "claim": r["claim"],
                "entity_ids": json.loads(r["entity_ids"]),
                "evidence_ids": json.loads(r["evidence_ids"]),
                "check": r["check_text"],
                "status": r["status"],
                "reason": r["reason"],
            }
            for r in rows
        ]
