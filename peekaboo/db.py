"""SQLite evidence database — stores findings with source URLs, excerpts, and metadata."""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "osint.db")


class EvidenceDB:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self._init()

    def _init(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_url TEXT NOT NULL,
                excerpt TEXT,
                date_checked TEXT,
                relevance TEXT,
                notes TEXT,
                node_type TEXT,
                node_id TEXT
            )
        """)
        conn.commit()
        conn.close()

    def add(self, source_url, excerpt="", relevance="", notes="", node_type="", node_id=""):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO evidence (source_url, excerpt, date_checked, relevance, notes, node_type, node_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (source_url, excerpt, datetime.utcnow().isoformat(), relevance, notes, node_type, node_id),
        )
        conn.commit()
        conn.close()

    def list_all(self):
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
        conn.close()
        cols = ["id", "source_url", "excerpt", "date_checked", "relevance", "notes", "node_type", "node_id"]
        return [dict(zip(cols, r)) for r in rows]

    def delete(self, evidence_id):
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        conn.commit()
        conn.close()

    def mark_removal(self, evidence_id):
        """Mark an evidence card for removal/correction (self-footprint cleanup)."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE evidence SET notes = 'REMOVAL_REQUESTED' WHERE id = ?", (evidence_id,))
        conn.commit()
        conn.close()

    def get_by_node(self, node_id):
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT * FROM evidence WHERE node_id = ? ORDER BY date_checked DESC", (node_id,)
        ).fetchall()
        conn.close()
        cols = ["id", "source_url", "excerpt", "date_checked", "relevance", "notes", "node_type", "node_id"]
        return [dict(zip(cols, r)) for r in rows]