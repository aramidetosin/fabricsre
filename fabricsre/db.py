"""PostgreSQL access for FabricSRE (psycopg 3). Small helpers, explicit SQL, no ORM."""
from __future__ import annotations

import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .nd import CallRecord

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "schema.sql"


class DB:
    def __init__(self, url: str):
        self.url = url

    @contextmanager
    def conn(self):
        with psycopg.connect(self.url, row_factory=dict_row) as c:
            yield c

    def init_schema(self) -> None:
        with self.conn() as c:
            c.execute(SCHEMA_FILE.read_text())

    # ------------------------------------------------------------ generic helpers
    def query(self, sql: str, params: Iterable | None = None) -> list[dict]:
        with self.conn() as c:
            return c.execute(sql, params or ()).fetchall()

    def execute(self, sql: str, params: Iterable | None = None) -> None:
        with self.conn() as c:
            c.execute(sql, params or ())

    def upsert(self, table: str, row: dict, key: list[str]) -> None:
        cols = list(row.keys())
        vals = [Jsonb(v) if isinstance(v, (dict, list)) and col == "raw" else v for col, v in row.items()]
        updates = ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c not in key)
        sql = (f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
               f"ON CONFLICT ({', '.join(key)}) DO UPDATE SET {updates}")
        with self.conn() as c:
            c.execute(sql, vals)

    def upsert_many(self, table: str, rows: list[dict], key: list[str]) -> int:
        if not rows:
            return 0
        cols = list(rows[0].keys())
        updates = ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c not in key)
        sql = (f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))}) "
               f"ON CONFLICT ({', '.join(key)}) DO UPDATE SET {updates}")
        with self.conn() as c:
            with c.cursor() as cur:
                cur.executemany(sql, [[Jsonb(r[col]) if isinstance(r[col], (dict, list)) and col == "raw" else r[col] for col in cols] for r in rows])
        return len(rows)

    # ------------------------------------------------------------ snapshots
    def start_snapshot(self, scope: str) -> int:
        with self.conn() as c:
            return c.execute("INSERT INTO snapshots (scope) VALUES (%s) RETURNING id", (scope,)).fetchone()["id"]

    def finish_snapshot(self, sid: int, status: str = "ok", notes: str = "") -> None:
        self.execute("UPDATE snapshots SET finished_at=now(), status=%s, notes=%s WHERE id=%s", (status, notes, sid))

    # ------------------------------------------------------------ audit sink for NDClient
    def record(self, rec: CallRecord) -> None:
        self.execute("INSERT INTO api_calls (method, path, status, ms, change_ref, note) VALUES (%s,%s,%s,%s,%s,%s)",
                     (rec.method, rec.path[:500], str(rec.status), rec.ms, rec.change_ref, rec.note))

    # ------------------------------------------------------------ timeline
    def add_timeline(self, events: list[dict]) -> int:
        n = 0
        with self.conn() as c:
            for e in events:
                cur = c.execute(
                    "INSERT INTO timeline_events (ts, source, fabric, device, actor, kind, severity, summary, ref, raw, fingerprint) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (fingerprint) DO NOTHING",
                    (e["ts"], e["source"], e.get("fabric"), e.get("device"), e.get("actor"), e.get("kind"), e.get("severity"),
                     e["summary"][:1000], e.get("ref"), Jsonb(e.get("raw")) if e.get("raw") is not None else None, e["fingerprint"]))
                n += cur.rowcount
        return n


def jdump(obj: Any) -> str:
    return json.dumps(obj, default=str, sort_keys=True)
