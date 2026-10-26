"""SQLite Database and Tamper-Evident Audit Log Subsystem.

Implements requirements:
- SADS 2.2.1 & 3.3: Storage Subsystem (SQLite/TimeSeries DB for metadata, alerts, audit log).
- SEC-REQ-5: Append-only, hash-chained audit log tamper-evident against post-hoc modification.
- SEC-REQ-1: Storage subsystem foundation.
"""

import sqlite3
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List


class DatabaseManager:
    """Manages SQLite storage for capture sessions and hash-chained audit logs."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            # Sessions table (SADS 3.3)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    interface TEXT NOT NULL,
                    filter TEXT,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    packet_count INTEGER DEFAULT 0,
                    byte_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active'
                )
            """)

            # AuditLog table with cryptographic hash-chaining (SEC-REQ-5, SADS 3.3)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TEXT NOT NULL
                )
            """)

    def record_audit_event(self, actor: str, action: str, details: Optional[str] = None) -> Dict[str, Any]:
        """Append a tamper-evident event to the hash-chained audit log (SEC-REQ-5)."""
        with self._conn:
            # Fetch previous entry's hash, or genesis seed
            cursor = self._conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            prev_hash = row["entry_hash"] if row else "GENESIS_HASH_PPS_0000000000000000000000000000"

            ts = datetime.now(timezone.utc).isoformat()
            details_str = details or ""

            # Compute entry hash: SHA-256(prev_hash + actor + action + details + timestamp)
            content_to_hash = f"{prev_hash}|{actor}|{action}|{details_str}|{ts}"
            entry_hash = hashlib.sha256(content_to_hash.encode("utf-8")).hexdigest()

            cursor = self._conn.execute(
                """
                INSERT INTO audit_log (prev_hash, entry_hash, actor, action, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (prev_hash, entry_hash, actor, action, details_str, ts),
            )
            return {
                "id": cursor.lastrowid,
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
                "actor": actor,
                "action": action,
                "details": details_str,
                "timestamp": ts,
            }

    def verify_audit_log_integrity(self) -> bool:
        """Verify that the cryptographic hash chain has not been tampered with (SEC-REQ-5)."""
        cursor = self._conn.execute("SELECT * FROM audit_log ORDER BY id ASC")
        rows = cursor.fetchall()

        expected_prev = "GENESIS_HASH_PPS_0000000000000000000000000000"
        for row in rows:
            if row["prev_hash"] != expected_prev:
                return False  # Chain broken

            content = f"{row['prev_hash']}|{row['actor']}|{row['action']}|{row['details']}|{row['timestamp']}"
            computed_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if row["entry_hash"] != computed_hash:
                return False  # Content altered

            expected_prev = row["entry_hash"]

        return True

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self._conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def close(self) -> None:
        self._conn.close()
