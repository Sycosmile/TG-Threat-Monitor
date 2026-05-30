# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — Database
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────

import sqlite3
import json
import os


def init_db(db_path: str):
    """Create tables if they don't exist."""
    dirpath = os.path.dirname(db_path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            channel     TEXT NOT NULL,
            message_id  INTEGER,
            timestamp   TEXT,
            severity    TEXT,
            iocs        TEXT,
            watchlist   TEXT,
            raw_text    TEXT,
            logged_at   TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS vt_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc         TEXT NOT NULL,
            ioc_type    TEXT,
            result      TEXT,
            checked_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def save_threat(db_path: str, parsed):
    """Save a parsed message to the database."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        INSERT INTO threats (channel, message_id, timestamp, severity, iocs, watchlist, raw_text)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        parsed.channel,
        parsed.message_id,
        parsed.timestamp,
        parsed.severity,
        json.dumps(parsed.iocs),
        json.dumps(parsed.watchlist_hits),
        parsed.raw_text[:2000],  # Cap raw text storage
    ))
    conn.commit()
    conn.close()


def save_vt_result(db_path: str, ioc: str, ioc_type: str, result: dict):
    """Save a VirusTotal lookup result."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        INSERT INTO vt_results (ioc, ioc_type, result)
        VALUES (?, ?, ?)
    """, (ioc, ioc_type, json.dumps(result)))
    conn.commit()
    conn.close()


def fetch_all(db_path: str, severity_filter: str = None, limit: int = 500) -> list:
    """Fetch logged threats, optionally filtered by severity."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if severity_filter:
        c.execute(
            "SELECT * FROM threats WHERE severity=? ORDER BY logged_at DESC LIMIT ?",
            (severity_filter, limit)
        )
    else:
        c.execute("SELECT * FROM threats ORDER BY logged_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def fetch_stats(db_path: str) -> dict:
    """Return summary statistics."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    stats = {}
    for sev in ("HIGH", "MEDIUM", "LOW"):
        c.execute("SELECT COUNT(*) FROM threats WHERE severity=?", (sev,))
        stats[sev] = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM threats")
    stats["TOTAL"] = c.fetchone()[0]
    c.execute("SELECT COUNT(DISTINCT channel) FROM threats")
    stats["CHANNELS"] = c.fetchone()[0]
    conn.close()
    return stats
