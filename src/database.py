# python src/database.py
import sqlite3
from pathlib import Path


class EventDB:
    """Simple SQLite persistence for raw events."""

    def __init__(self, db_path: str | Path = "events.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_table()

    def _create_table(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT    NOT NULL,
                source      TEXT    NOT NULL,
                raw_event   TEXT    NOT NULL
            )
            """
        )
        self.conn.commit()

    def insert_event(self, received_at: str, source: str, raw_event: str):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO events (received_at, source, raw_event) VALUES (?, ?, ?)",
            (received_at, source, raw_event),
        )
        self.conn.commit()
        return cur.lastrowid

    def fetch_all(self):
        cur = self.conn.cursor()
        cur.execute("SELECT id, received_at, source, raw_event FROM events ORDER BY id")
        return cur.fetchall()

    def close(self):
        self.conn.close()