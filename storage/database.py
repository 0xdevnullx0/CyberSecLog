"""SQLite persistence layer.

Responsibilities:
- Store raw intelligence items so duplicate items are not re-processed.
- Store generated briefings for audit / replay.
- Provide simple query helpers used by the rest of the app.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator

import config


# ── Schema ─────────────────────────────────────────────────────────────────────
_CREATE_ITEMS = """
CREATE TABLE IF NOT EXISTS intelligence_items (
    id          TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    category    TEXT NOT NULL,       -- cve | news | threat_actor | advisory
    title       TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    published   TEXT,
    severity    TEXT,
    cvss_score  REAL,
    risk_score  REAL DEFAULT 0,
    tags        TEXT,                -- JSON array
    raw_data    TEXT,                -- JSON blob
    seen_at     TEXT NOT NULL
);
"""

_CREATE_BRIEFINGS = """
CREATE TABLE IF NOT EXISTS briefings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    date_label  TEXT NOT NULL,       -- YYYY-MM-DD
    content     TEXT NOT NULL,       -- full HTML
    items_count INTEGER DEFAULT 0
);
"""

_CREATE_SEEN = """
CREATE TABLE IF NOT EXISTS seen_ids (
    source_id TEXT PRIMARY KEY,
    seen_at   TEXT NOT NULL
);
"""


# ── Connection helper ──────────────────────────────────────────────────────────
@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they do not exist yet."""
    with _get_conn() as conn:
        conn.executescript(_CREATE_ITEMS + _CREATE_BRIEFINGS + _CREATE_SEEN)


# ── Deduplication helpers ──────────────────────────────────────────────────────
def is_seen(source_id: str) -> bool:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM seen_ids WHERE source_id = ?", (source_id,)
        ).fetchone()
    return row is not None


def mark_seen(source_id: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO seen_ids (source_id, seen_at) VALUES (?,?)",
            (source_id, now),
        )


# ── Item storage ───────────────────────────────────────────────────────────────
def upsert_item(item: dict) -> None:
    """Insert or update an intelligence item.  `item` must have an `id` key."""
    now = datetime.now(timezone.utc).isoformat()
    tags = json.dumps(item.get("tags", []))
    raw = json.dumps(item.get("raw_data", {}))

    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO intelligence_items
                (id, source, category, title, description, url, published,
                 severity, cvss_score, risk_score, tags, raw_data, seen_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                risk_score = excluded.risk_score,
                tags       = excluded.tags,
                seen_at    = excluded.seen_at
            """,
            (
                item["id"],
                item.get("source", "unknown"),
                item.get("category", "unknown"),
                item.get("title", ""),
                item.get("description", ""),
                item.get("url", ""),
                item.get("published", ""),
                item.get("severity", ""),
                item.get("cvss_score"),
                item.get("risk_score", 0.0),
                tags,
                raw,
                now,
            ),
        )
    mark_seen(item["id"])


def get_recent_items(hours: int = 26) -> list[dict]:
    """Return items seen within the last `hours` hours, ordered by risk_score."""
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM intelligence_items
            WHERE datetime(seen_at) >= datetime('now', ?)
            ORDER BY risk_score DESC
            """,
            (f"-{hours} hours",),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Briefing storage ───────────────────────────────────────────────────────────
def save_briefing(content: str, items_count: int) -> int:
    now = datetime.now(timezone.utc).isoformat()
    date_label = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO briefings (created_at, date_label, content, items_count) VALUES (?,?,?,?)",
            (now, date_label, content, items_count),
        )
        return cur.lastrowid


def get_latest_briefing() -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM briefings ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row else None
