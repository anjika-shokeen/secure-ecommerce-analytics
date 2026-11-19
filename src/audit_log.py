"""Phase 6 - Audit logging in SQLite.

Every important action (logins, decryptions, audit-log views) is written to
logs/audit.db with: timestamp, username, role, action, resource, status, reason.
The module exposes only INSERT and SELECT - there is no update or delete function.

LIMITATION (documented in SECURITY_WRITEUP.md): a local SQLite file is not
tamper-evident; production would ship logs to a write-once external store / SIEM.

Run (smoke test):  python src/audit_log.py
"""
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
DB_PATH = LOG_DIR / "audit.db"

SUCCESS, FAILED, DENIED = "SUCCESS", "FAILED", "DENIED"


def _connect(db_path=None):
    path = Path(db_path) if db_path else DB_PATH
    path.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username  TEXT,
            role      TEXT,
            action    TEXT NOT NULL,
            resource  TEXT,
            status    TEXT NOT NULL,
            reason    TEXT
        )""")
    return conn


def log_event(username, role, action, resource="", status=SUCCESS, reason="", db_path=None):
    conn = _connect(db_path)
    try:
        with conn:      # commits the insert
            conn.execute(
                "INSERT INTO audit_log (timestamp, username, role, action, resource, status, reason)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, role, action,
                 resource, status, reason))
    finally:
        conn.close()    # release the file (Windows cannot delete an open database)


def get_events(limit=1000, db_path=None) -> pd.DataFrame:
    conn = _connect(db_path)
    try:
        return pd.read_sql_query(
            "SELECT id, timestamp, username, role, action, resource, status, reason "
            "FROM audit_log ORDER BY id DESC LIMIT ?", conn, params=(limit,))
    finally:
        conn.close()


if __name__ == "__main__":
    log_event("admin", "Admin", "SMOKE_TEST", "audit_log.py", SUCCESS, "module self-test")
    print(get_events(limit=5).to_string(index=False))
