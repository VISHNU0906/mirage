"""SQLite persistence layer (stdlib ``sqlite3`` -- zero external dependency).

Tables: ``users``, ``documents``, ``messages``, ``email_log``.  Each row that
belongs to a tenant carries ``user_id`` so the BOLA / cross-tenant isolation
demos have something concrete to (fail to) enforce.

A :class:`Database` instance owns one connection.  ``:memory:`` databases get a
single shared connection so the whole app + test sees the same data.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name    TEXT DEFAULT '',
    role         TEXT DEFAULT 'user',
    tenant_id    INTEGER DEFAULT 0,
    created_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    role        TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS email_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    recipient   TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  REAL NOT NULL
);
"""


class Database:
    def __init__(self, path: str = "mirage.db"):
        self.path = path
        self._lock = threading.Lock()
        # check_same_thread=False because uvicorn serves requests on a
        # threadpool; we serialise writes with our own lock.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    # --- users -----------------------------------------------------------
    def create_user(
        self,
        email: str,
        password_hash: str,
        full_name: str = "",
        role: str = "user",
        tenant_id: int = 0,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO users (email, password_hash, full_name, role, "
                "tenant_id, created_at) VALUES (?,?,?,?,?,?)",
                (email, password_hash, full_name, role, tenant_id, time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def get_user_by_email(self, email: str) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        return cur.fetchone()

    def get_user(self, user_id: int) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()

    def update_user_fields(self, user_id: int, fields: dict) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._lock:
            self._conn.execute(
                f"UPDATE users SET {cols} WHERE id = ?",
                (*fields.values(), user_id),
            )
            self._conn.commit()

    # --- documents -------------------------------------------------------
    def add_document(self, user_id: int, title: str, content: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO documents (user_id, title, content, created_at) "
                "VALUES (?,?,?,?)",
                (user_id, title, content, time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def get_document(self, doc_id: int) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
        return cur.fetchone()

    def list_documents(self, user_id: int) -> List[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM documents WHERE user_id = ? ORDER BY id", (user_id,)
        )
        return cur.fetchall()

    def all_documents(self) -> List[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM documents ORDER BY id")
        return cur.fetchall()

    # --- messages --------------------------------------------------------
    def add_message(self, user_id: int, role: str, content: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO messages (user_id, role, content, created_at) "
                "VALUES (?,?,?,?)",
                (user_id, role, content, time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    # --- email log -------------------------------------------------------
    def log_email(self, user_id: int, recipient: str, body: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO email_log (user_id, recipient, body, created_at) "
                "VALUES (?,?,?,?)",
                (user_id, recipient, body, time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def emails_for(self, user_id: int) -> List[sqlite3.Row]:
        cur = self._conn.execute(
            "SELECT * FROM email_log WHERE user_id = ? ORDER BY id", (user_id,)
        )
        return cur.fetchall()
