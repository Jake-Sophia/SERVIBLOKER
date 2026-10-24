"""Estado observado y límites persistentes; sin privilegios de red."""
from __future__ import annotations

import hashlib
import contextlib
import os
import sqlite3
import time


class VirtualState:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        self.path = os.path.join(data_dir, "virtual.sqlite3")
        # Crear con permisos privados antes de conectar.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS limits (key TEXT PRIMARY KEY, start INTEGER, count INTEGER, expires INTEGER);
                CREATE TABLE IF NOT EXISTS contacts (token TEXT PRIMARY KEY, at INTEGER, public_ip TEXT);
                CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY CHECK(id=1),
                    at INTEGER, payload TEXT);
            ''')
            if "expires" not in {row[1] for row in db.execute("PRAGMA table_info(limits)")}:
                db.execute("ALTER TABLE limits ADD COLUMN expires INTEGER NOT NULL DEFAULT 0")

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    def allow(self, key: str, limit: int = 10, window: int = 900) -> bool:
        key = hashlib.sha256(key.encode()).hexdigest()
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM limits WHERE expires <= ?", (now,))
            row = db.execute("SELECT count FROM limits WHERE key=?", (key,)).fetchone()
            if row and row[0] >= limit:
                return False
            db.execute('''INSERT INTO limits VALUES (?, ?, 1, ?)
                ON CONFLICT(key) DO UPDATE SET count=count+1''', (key, now, now + window))
        return True

    def observe(self, payload: dict):
        import json
        with self.connect() as db:
            for session in payload.get("sessions", []):
                db.execute("INSERT OR REPLACE INTO contacts VALUES(?,?,?)", (session["token"], int(time.time()), session.get("public_ip", "")))
            db.execute("INSERT OR REPLACE INTO observations VALUES(1, ?, ?)",
                       (int(time.time()), json.dumps(payload)))

    def observed(self) -> dict:
        import json
        with self.connect() as db:
            row = db.execute("SELECT at,payload FROM observations WHERE id=1").fetchone()
        if not row:
            return {"at": 0, "healthy": False, "sessions": [], "error": "controlador_sin_contacto"}
        return {**json.loads(row[1]), "at": row[0], "fresh": time.time() - row[0] < 20}

    def learn(self, name: str, addresses: list[tuple[str, int]]):
        now = int(time.time())
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS answers (name TEXT, ip TEXT, expires INTEGER, PRIMARY KEY(name,ip))")
            db.execute("DELETE FROM answers WHERE expires<=?", (now,))
            for ip, ttl in addresses:
                if ttl > 0:
                    db.execute("INSERT OR REPLACE INTO answers VALUES(?,?,?)", (name, ip, now + min(ttl, 300)))
            db.execute("DELETE FROM answers WHERE rowid IN (SELECT rowid FROM answers ORDER BY expires DESC LIMIT -1 OFFSET 20000)")

    def answers(self):
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS answers (name TEXT, ip TEXT, expires INTEGER, PRIMARY KEY(name,ip))")
            return list(db.execute("SELECT name,ip,expires FROM answers WHERE expires>?", (int(time.time()),)))

    def contacts(self):
        with self.connect() as db:
            return {row[0]: {"at": row[1], "public_ip": row[2]}
                    for row in db.execute("SELECT token,at,public_ip FROM contacts")}
