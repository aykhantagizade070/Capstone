"""Storage layer for baselines and logs."""

from __future__ import annotations

import sqlite3
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, List

from fim_agent.core.events import Event, EventType, Severity


class Storage:
    """SQLite-backed storage for file baseline and event data."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Allow usage across watchdog threads; SQLite serializes writes internally.
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    @staticmethod
    def _norm_path(path: str) -> str:
        """Normalize paths consistently for DB reads/writes."""
        return os.path.normcase(os.path.abspath(path))

    def init_schema(self) -> None:
        """Create tables if they do not exist."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                path TEXT UNIQUE,
                hash TEXT,
                first_seen TEXT,
                last_seen TEXT,
                last_event_type TEXT,
                is_private INTEGER DEFAULT 0
            )
            """
        )
        # Events table for timeline; includes minimal required columns plus extras.
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                path TEXT,
                old_hash TEXT,
                new_hash TEXT,
                severity TEXT,
                mitre_tags TEXT,
                message TEXT,
                user TEXT,
                user_type TEXT,
                process_name TEXT,
                sha256 TEXT,
                previous_sha256 TEXT,
                hash_changed INTEGER,
                content_classification TEXT,
                risk_score INTEGER,
                ai_classification TEXT,
                ai_risk_score INTEGER,
                ai_risk_reason TEXT,
                is_alert INTEGER,
                old_path TEXT,
                requires_admin_approval INTEGER,
                admin_approved INTEGER,
                content_score INTEGER,
                content_flags TEXT,
                ai_recommendation TEXT,
                classification_matches TEXT
            )
            """
        )
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
        self._ensure_event_columns()
        self._ensure_files_columns()
        self.conn.commit()

    def _ensure_event_columns(self) -> None:
        """Add missing event columns for forward compatibility."""
        cursor = self.conn.execute("PRAGMA table_info(events)")
        existing = {row[1] for row in cursor.fetchall()}
        needed = {
            "user": "TEXT",
            "user_type": "TEXT",
            "process_name": "TEXT",
            "sha256": "TEXT",
            "previous_sha256": "TEXT",
            "hash_changed": "INTEGER",
            "content_classification": "TEXT",
            "risk_score": "INTEGER",
            "ai_classification": "TEXT",
            "ai_risk_score": "INTEGER",
            "ai_risk_reason": "TEXT",
            "mitre_tags": "TEXT",
            "old_hash": "TEXT",
            "new_hash": "TEXT",
            "severity": "TEXT",
            "message": "TEXT",
            "is_alert": "INTEGER",
            "old_path": "TEXT",
            "requires_admin_approval": "INTEGER",
            "admin_approved": "INTEGER",
            "sticky_private": "INTEGER",
            "effective_classification": "TEXT",
        }
        for col, col_type in needed.items():
            if col not in existing:
                self.conn.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")

    def _ensure_files_columns(self) -> None:
        """Add missing files columns for forward compatibility."""
        cursor = self.conn.execute("PRAGMA table_info(files)")
        existing = {row[1] for row in cursor.fetchall()}
        needed = {
            "is_private": "INTEGER DEFAULT 0",
        }
        for col, col_type in needed.items():
            if col not in existing:
                self.conn.execute(f"ALTER TABLE files ADD COLUMN {col} {col_type}")

    def get_file(self, path: str) -> Optional[Dict[str, Any]]:
        """Fetch a file record by path."""
        norm_path = self._norm_path(path)
        cursor = self.conn.execute("SELECT * FROM files WHERE path = ?", (norm_path,))
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)
    
    def has_seen_path(self, path: str) -> bool:
        """
        Check if a file path has been seen before in the baseline/storage.
        
        Returns True if there is already a baseline/file record for this path,
        False if this path has never been stored before.
        """
        record = self.get_file(path)
        return record is not None

    def upsert_file(self, path: str, file_hash: str, event_type: str, timestamp: datetime) -> None:
        """Insert or update a file record."""
        norm_path = self._norm_path(path)
        ts = timestamp.isoformat()
        self.conn.execute(
            """
            INSERT INTO files (path, hash, first_seen, last_seen, last_event_type)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                hash=excluded.hash,
                last_seen=excluded.last_seen,
                last_event_type=excluded.last_event_type
            """,
            (norm_path, file_hash, ts, ts, event_type),
        )
        self.conn.commit()

    def count_files(self) -> int:
        """Return number of file records."""
        cursor = self.conn.execute("SELECT COUNT(*) as c FROM files")
        row = cursor.fetchone()
        return int(row["c"]) if row else 0

    def update_file_path(self, old_path: str, new_path: str) -> None:
        """
        When a file is renamed inside a monitored directory, keep its baseline hash
        but move it to the new path.
        If old_path is not found, just do nothing.
        If new_path already exists, merge/update it with the old_path's data.
        """
        # Check if old_path exists
        old_norm = self._norm_path(old_path)
        new_norm = self._norm_path(new_path)

        old_record = self.get_file(old_norm)
        if not old_record:
            return
        
        # Check if new_path already exists
        new_record = self.get_file(new_norm)
        
        if new_record:
            # new_path already exists - merge: update new_path with old_path's data, then delete old_path
            # Use the old_path's hash (the file being moved is what we're tracking)
            # Preserve the older first_seen (original file's history)
            # Use the more recent last_seen
            old_first_seen = old_record.get("first_seen")
            new_first_seen = new_record.get("first_seen")
            # Use the earlier first_seen (preserve original history)
            # ISO format strings are lexicographically sortable
            if old_first_seen and new_first_seen:
                first_seen = min(old_first_seen, new_first_seen)
            else:
                first_seen = old_first_seen or new_first_seen
            
            old_last_seen = old_record.get("last_seen")
            new_last_seen = new_record.get("last_seen")
            # Use the more recent last_seen
            if old_last_seen and new_last_seen:
                last_seen = max(old_last_seen, new_last_seen)
            else:
                last_seen = old_last_seen or new_last_seen
            
            self.conn.execute(
                """
                UPDATE files
                SET hash = ?,
                    first_seen = ?,
                    last_seen = ?,
                    last_event_type = ?
                WHERE path = ?
                """,
                (
                    old_record["hash"],  # Use old_path's hash (file being moved)
                    first_seen,  # Preserve earlier first_seen
                    last_seen,  # Use more recent last_seen
                    old_record["last_event_type"],
                    new_norm,
                ),
            )
            # Delete the old_path row
            self.conn.execute("DELETE FROM files WHERE path = ?", (old_norm,))
        else:
            # new_path doesn't exist - simple update
            self.conn.execute(
                """
                UPDATE files
                SET path = ?
                WHERE path = ?
                """,
                (new_norm, old_norm),
            )
        self.conn.commit()

    def record_event(self, event: Event) -> None:
        """Persist an Event to the events table."""
        try:
            norm_path = self._norm_path(event.path)
            norm_old_path = self._norm_path(event.old_path) if event.old_path else None
            self.conn.execute(
                """
                INSERT INTO events (
                    timestamp, event_type, path, old_hash, new_hash, severity, mitre_tags, message,
                    user, user_type, process_name, sha256, previous_sha256, hash_changed,
                    content_classification, risk_score, ai_classification, ai_risk_score, ai_risk_reason, is_alert, old_path,
                    requires_admin_approval, admin_approved, content_score, content_flags, ai_recommendation, classification_matches,
                    sticky_private, effective_classification
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp.isoformat(),
                    event.event_type,
                    norm_path,
                    event.old_hash,
                    event.new_hash,
                    event.severity,
                    json.dumps(event.mitre_tags),
                    event.message,
                    event.user,
                    event.user_type,
                    event.process_name,
                    event.sha256,
                    event.previous_sha256,
                    int(event.hash_changed) if event.hash_changed is not None else None,
                    event.content_classification,
                    event.risk_score,
                    event.ai_classification,
                    event.ai_risk_score,
                    event.ai_risk_reason,
                    int(event.is_alert) if event.is_alert is not None else 0,
                    norm_old_path,
                    int(event.requires_admin_approval) if event.requires_admin_approval is not None else 0,
                    int(event.admin_approved) if event.admin_approved is not None else None,
                    event.content_score,
                    json.dumps(event.content_flags) if event.content_flags else None,
                    event.ai_recommendation,
                    json.dumps(event.classification_matches) if event.classification_matches else None,
                    int(event.sticky_private) if event.sticky_private is not None else None,
                    event.effective_classification,
                ),
            )
            self.conn.commit()
        except Exception as e:
            # Log error but don't crash - events should still be logged to file
            import sys
            print(f"Warning: Failed to persist event to database: {e}", file=sys.stderr)
            self.conn.rollback()

    # Backward-compatible alias
    def log_event(self, event: Event) -> None:
        self.record_event(event)

    def remove_recent_delete_event(self, path: str, within_seconds: float = 2.0) -> bool:
        """
        Remove the most recent DELETE event for the given path within the time window.
        Returns True if an event was removed, False otherwise.
        Used to clean up DELETE events that are actually part of a move operation.
        """
        norm_path = self._norm_path(path)
        cutoff = (datetime.utcnow() - timedelta(seconds=within_seconds)).isoformat()
        cursor = self.conn.execute(
            """
            DELETE FROM events
            WHERE path = ? AND event_type = 'delete' AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (norm_path, cutoff),
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def get_is_private(self, path: str) -> int:
        """Get persisted private state for a file path (0/1). Creates a row if missing."""
        norm_path = self._norm_path(path)
        row = self.conn.execute("SELECT is_private FROM files WHERE path = ?", (norm_path,)).fetchone()
        if row is None:
            # Create placeholder file row with default is_private=0; hash is unknown here
            ts = datetime.utcnow().isoformat()
            self.conn.execute(
                """
                INSERT INTO files (path, hash, first_seen, last_seen, last_event_type, is_private)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO NOTHING
                """,
                (norm_path, None, ts, ts, None, 0),
            )
            self.conn.commit()
            return 0
        val = row["is_private"]
        return int(val) if val is not None else 0

    def set_is_private(self, path: str, is_private: int) -> None:
        """Persist private state (0/1) for a file path. Creates a row if missing."""
        norm_path = self._norm_path(path)
        ts = datetime.utcnow().isoformat()
        self.conn.execute(
            """
            INSERT INTO files (path, hash, first_seen, last_seen, last_event_type, is_private)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                is_private=excluded.is_private,
                last_seen=excluded.last_seen
            """,
            (norm_path, None, ts, ts, None, int(is_private)),
        )
        self.conn.commit()

    def get_events(
        self,
        from_ts: Optional[datetime] = None,
        to_ts: Optional[datetime] = None,
        path_filter: Optional[str] = None,
        severity: Optional[Severity] = None,
        classification: Optional[str] = None,
        min_risk: Optional[int] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        order_desc: bool = False,
    ) -> List[Event]:
        """
        Return events with optional filters and pagination.
        
        Args:
            from_ts: Start timestamp filter
            to_ts: End timestamp filter
            path_filter: Path substring filter
            severity: Severity filter (low/medium/high)
            classification: Content classification filter
            min_risk: Minimum risk_score filter
            limit: Maximum number of events to return
            offset: Number of events to skip
            order_desc: If True, order by timestamp DESC (newest first), else ASC (oldest first)
        """
        clauses = []
        params: List[Any] = []

        if from_ts:
            clauses.append("timestamp >= ?")
            params.append(from_ts.isoformat())
        if to_ts:
            clauses.append("timestamp <= ?")
            params.append(to_ts.isoformat())
        if path_filter:
            clauses.append("path LIKE ?")
            params.append(f"%{path_filter}%")
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if classification:
            clauses.append("content_classification = ?")
            params.append(classification)
        if min_risk is not None:
            clauses.append("risk_score >= ?")
            params.append(min_risk)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "DESC" if order_desc else "ASC"
        query = f"SELECT * FROM events {where} ORDER BY timestamp {order}"
        
        if limit is not None:
            query += f" LIMIT {limit}"
        if offset is not None:
            query += f" OFFSET {offset}"
        
        cursor = self.conn.execute(query, params)

        events: List[Event] = []
        for row in cursor.fetchall():
            # sqlite3.Row supports direct key access; use get() with None default for optional fields
            row_dict = dict(row)
            event = Event(
                timestamp=datetime.fromisoformat(row["timestamp"]),
                event_type=row["event_type"],  # type: ignore[arg-type]
                path=row["path"],
                old_hash=row_dict.get("old_hash"),
                new_hash=row_dict.get("new_hash"),
                severity=row["severity"],  # type: ignore[arg-type]
                mitre_tags=json.loads(row_dict.get("mitre_tags") or "[]"),
                message=row["message"],
                user=row_dict.get("user"),
                user_type=row_dict.get("user_type"),
                process_name=row_dict.get("process_name"),
                sha256=row_dict.get("sha256"),
                previous_sha256=row_dict.get("previous_sha256"),
                hash_changed=bool(row_dict["hash_changed"]) if row_dict.get("hash_changed") is not None else None,
                content_classification=row_dict.get("content_classification"),
                risk_score=int(row_dict["risk_score"]) if row_dict.get("risk_score") is not None else None,
                ai_classification=row_dict.get("ai_classification"),
                ai_risk_score=int(row_dict["ai_risk_score"]) if row_dict.get("ai_risk_score") is not None else None,
                ai_risk_reason=row_dict.get("ai_risk_reason"),
                is_alert=bool(row_dict["is_alert"]) if row_dict.get("is_alert") is not None else None,
                old_path=row_dict.get("old_path"),
                requires_admin_approval=bool(row_dict["requires_admin_approval"]) if row_dict.get("requires_admin_approval") is not None else None,
                admin_approved=bool(row_dict["admin_approved"]) if row_dict.get("admin_approved") is not None else None,
                content_score=int(row_dict["content_score"]) if row_dict.get("content_score") is not None else None,
                content_flags=json.loads(row_dict["content_flags"]) if row_dict.get("content_flags") else None,
                ai_recommendation=row_dict.get("ai_recommendation"),
                classification_matches=json.loads(row_dict["classification_matches"]) if row_dict.get("classification_matches") else None,
                sticky_private=bool(row_dict["sticky_private"]) if row_dict.get("sticky_private") is not None else None,
                effective_classification=row_dict.get("effective_classification"),
            )
            # Store ID as an attribute (Event model doesn't have id field, but we can attach it)
            event.id = row_dict.get("id")  # type: ignore[attr-defined]
            events.append(event)
        return events

    def get_event_by_id(self, event_id: int) -> Optional[Event]:
        """Get a single event by its database ID."""
        cursor = self.conn.execute("SELECT * FROM events WHERE id = ?", (event_id,))
        row = cursor.fetchone()
        if not row:
            return None
        
        row_dict = dict(row)
        event = Event(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            event_type=row["event_type"],  # type: ignore[arg-type]
            path=row["path"],
            old_hash=row_dict.get("old_hash"),
            new_hash=row_dict.get("new_hash"),
            severity=row["severity"],  # type: ignore[arg-type]
            mitre_tags=json.loads(row_dict.get("mitre_tags") or "[]"),
            message=row["message"],
            user=row_dict.get("user"),
            user_type=row_dict.get("user_type"),
            process_name=row_dict.get("process_name"),
            sha256=row_dict.get("sha256"),
            previous_sha256=row_dict.get("previous_sha256"),
            hash_changed=bool(row_dict["hash_changed"]) if row_dict.get("hash_changed") is not None else None,
            content_classification=row_dict.get("content_classification"),
            risk_score=int(row_dict["risk_score"]) if row_dict.get("risk_score") is not None else None,
            ai_classification=row_dict.get("ai_classification"),
            ai_risk_score=int(row_dict["ai_risk_score"]) if row_dict.get("ai_risk_score") is not None else None,
            ai_risk_reason=row_dict.get("ai_risk_reason"),
            is_alert=bool(row_dict["is_alert"]) if row_dict.get("is_alert") is not None else None,
            old_path=row_dict.get("old_path"),
            requires_admin_approval=bool(row_dict["requires_admin_approval"]) if row_dict.get("requires_admin_approval") is not None else None,
            admin_approved=bool(row_dict["admin_approved"]) if row_dict.get("admin_approved") is not None else None,
            content_score=int(row_dict["content_score"]) if row_dict.get("content_score") is not None else None,
            content_flags=json.loads(row_dict["content_flags"]) if row_dict.get("content_flags") else None,
            ai_recommendation=row_dict.get("ai_recommendation"),
            classification_matches=json.loads(row_dict["classification_matches"]) if row_dict.get("classification_matches") else None,
            sticky_private=bool(row_dict["sticky_private"]) if row_dict.get("sticky_private") is not None else None,
            effective_classification=row_dict.get("effective_classification"),
        )
        event.id = row_dict.get("id")  # type: ignore[attr-defined]
        return event

    def get_stats_summary(self) -> Dict[str, Any]:
        """Get high-level statistics about events."""
        # Total events
        total_events = self.conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
        
        # Total alerts
        total_alerts = self.conn.execute("SELECT COUNT(*) as c FROM events WHERE is_alert = 1").fetchone()["c"]
        
        # Counts by severity
        severity_counts: Dict[str, int] = {}
        for row in self.conn.execute("SELECT severity, COUNT(*) as c FROM events GROUP BY severity"):
            severity_counts[row["severity"]] = row["c"]
        
        # Counts by event_type
        event_type_counts: Dict[str, int] = {}
        for row in self.conn.execute("SELECT event_type, COUNT(*) as c FROM events GROUP BY event_type"):
            event_type_counts[row["event_type"]] = row["c"]
        
        # Counts by classification
        classification_counts: Dict[str, int] = {}
        for row in self.conn.execute(
            "SELECT content_classification, COUNT(*) as c FROM events WHERE content_classification IS NOT NULL GROUP BY content_classification"
        ):
            classification_counts[row["content_classification"]] = row["c"]
        
        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "counts_by_severity": severity_counts,
            "counts_by_event_type": event_type_counts,
            "counts_by_classification": classification_counts,
        }

    def get_risk_pie_stats(self) -> Dict[str, int]:
        """
        Get risk score distribution in buckets for pie chart visualization.
        Buckets: low (0-29), medium (30-59), high (60-79), critical (80+)
        """
        buckets = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }
        
        for row in self.conn.execute("SELECT risk_score FROM events WHERE risk_score IS NOT NULL"):
            score = row["risk_score"]
            if score < 30:
                buckets["low"] += 1
            elif score < 60:
                buckets["medium"] += 1
            elif score < 80:
                buckets["high"] += 1
            else:
                buckets["critical"] += 1
        
        return buckets

    def get_pending_admin_events(self, limit: int = 10) -> List[Event]:
        """
        Get events that require admin approval but haven't been approved yet.
        
        Returns events where requires_admin_approval is true and admin_approved is NULL/None/0.
        Ordered by id descending (newest first).
        """
        cursor = self.conn.execute(
            """
            SELECT * FROM events
            WHERE requires_admin_approval = 1 AND (admin_approved IS NULL OR admin_approved = 0)
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        
        events: List[Event] = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            event = Event(
                timestamp=datetime.fromisoformat(row["timestamp"]),
                event_type=row["event_type"],  # type: ignore[arg-type]
                path=row["path"],
                old_hash=row_dict.get("old_hash"),
                new_hash=row_dict.get("new_hash"),
                severity=row["severity"],  # type: ignore[arg-type]
                mitre_tags=json.loads(row_dict.get("mitre_tags") or "[]"),
                message=row["message"],
                user=row_dict.get("user"),
                user_type=row_dict.get("user_type"),
                process_name=row_dict.get("process_name"),
                sha256=row_dict.get("sha256"),
                previous_sha256=row_dict.get("previous_sha256"),
                hash_changed=bool(row_dict["hash_changed"]) if row_dict.get("hash_changed") is not None else None,
                content_classification=row_dict.get("content_classification"),
                risk_score=int(row_dict["risk_score"]) if row_dict.get("risk_score") is not None else None,
                ai_classification=row_dict.get("ai_classification"),
                ai_risk_score=int(row_dict["ai_risk_score"]) if row_dict.get("ai_risk_score") is not None else None,
                ai_risk_reason=row_dict.get("ai_risk_reason"),
                is_alert=bool(row_dict["is_alert"]) if row_dict.get("is_alert") is not None else None,
                old_path=row_dict.get("old_path"),
                requires_admin_approval=bool(row_dict["requires_admin_approval"]) if row_dict.get("requires_admin_approval") is not None else None,
                admin_approved=bool(row_dict["admin_approved"]) if row_dict.get("admin_approved") is not None else None,
                content_score=int(row_dict["content_score"]) if row_dict.get("content_score") is not None else None,
                content_flags=json.loads(row_dict["content_flags"]) if row_dict.get("content_flags") else None,
                ai_recommendation=row_dict.get("ai_recommendation"),
                classification_matches=json.loads(row_dict["classification_matches"]) if row_dict.get("classification_matches") else None,
            )
            event.id = row_dict.get("id")  # type: ignore[attr-defined]
            events.append(event)
        return events

    def set_admin_approved(self, event_id: int, approved: bool) -> Optional[Event]:
        """
        Update the admin_approved status for an event.
        
        Args:
            event_id: The database ID of the event
            approved: True to approve, False to reject
            
        Returns:
            The updated Event object, or None if event not found
        """
        # Update the event
        self.conn.execute(
            "UPDATE events SET admin_approved = ? WHERE id = ?",
            (1 if approved else 0, event_id)
        )
        self.conn.commit()
        
        # Return the updated event
        return self.get_event_by_id(event_id)


__all__ = ["Storage"]
