"""
Database Manager
Handles all database operations for security event logging.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from contextlib import contextmanager

from config.settings import Settings
from utils.logger import setup_logger

logger = setup_logger(__name__)


class DatabaseManager:
    """Manages SQLite database for security events."""

    def __init__(self, db_path: str = None):
        """
        Initialize database manager.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or Settings.DATABASE_PATH
        self.init_database()
        logger.info(f"Database initialized at {self.db_path}")

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()

    def init_database(self):
        """Initialize database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Events table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_id INTEGER,
                    description TEXT,
                    raw_data TEXT,
                    threat_score INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Create index on timestamp for faster queries
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                ON events(timestamp)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_severity 
                ON events(severity)
            """
            )

            # Alerts table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER,
                    alert_type TEXT NOT NULL,
                    message TEXT,
                    recommendations TEXT,
                    triggered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    acknowledged INTEGER DEFAULT 0,
                    FOREIGN KEY (event_id) REFERENCES events(id)
                )
            """
            )

            # System stats table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS system_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    cpu_percent REAL,
                    memory_percent REAL,
                    memory_used_mb REAL,
                    disk_usage_percent REAL,
                    network_bytes_sent INTEGER,
                    network_bytes_recv INTEGER,
                    active_connections INTEGER
                )
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_stats_timestamp 
                ON system_stats(timestamp)
            """
            )

            logger.info("Database schema initialized successfully")

    def add_event(
        self,
        event_type: str,
        severity: str,
        source: str,
        description: str,
        event_id: int = None,
        raw_data: dict = None,
        threat_score: int = 0,
    ) -> int:
        """
        Add a security event to the database.

        Args:
            event_type: Type of event (e.g., "Login", "File Change")
            severity: Severity level ("Critical", "Warning", "Info")
            source: Event source (e.g., "Windows Event Log", "File Monitor")
            description: Human-readable description
            event_id: Optional Windows event ID
            raw_data: Optional dictionary of raw event data
            threat_score: Threat score (0-100)

        Returns:
            int: ID of inserted event
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO events 
                (timestamp, event_type, severity, source, event_id, description, raw_data, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    datetime.now().isoformat(),
                    event_type,
                    severity,
                    source,
                    event_id,
                    description,
                    json.dumps(raw_data) if raw_data else None,
                    threat_score,
                ),
            )
            return cursor.lastrowid

    def add_alert(
        self, event_id: int, alert_type: str, message: str, recommendations: str = None
    ) -> int:
        """
        Add an alert to the database.

        Args:
            event_id: Associated event ID
            alert_type: Type of alert
            message: Alert message
            recommendations: Recommended actions

        Returns:
            int: ID of inserted alert
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (event_id, alert_type, message, recommendations)
                VALUES (?, ?, ?, ?)
            """,
                (event_id, alert_type, message, recommendations),
            )
            return cursor.lastrowid

    def add_system_stat(
        self,
        cpu_percent: float,
        memory_percent: float,
        memory_used_mb: float,
        disk_usage_percent: float,
        network_bytes_sent: int,
        network_bytes_recv: int,
        active_connections: int,
    ):
        """Add system statistics to database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO system_stats 
                (timestamp, cpu_percent, memory_percent, memory_used_mb, 
                 disk_usage_percent, network_bytes_sent, network_bytes_recv, 
                 active_connections)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    datetime.now().isoformat(),
                    cpu_percent,
                    memory_percent,
                    memory_used_mb,
                    disk_usage_percent,
                    network_bytes_sent,
                    network_bytes_recv,
                    active_connections,
                ),
            )

    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: str = None,
        event_type: str = None,
        start_date: str = None,
        end_date: str = None,
    ) -> List[Dict]:
        """
        Get events with optional filtering.

        Args:
            limit: Maximum number of events to return
            offset: Offset for pagination
            severity: Filter by severity
            event_type: Filter by event type
            start_date: Filter by start date (ISO format)
            end_date: Filter by end date (ISO format)

        Returns:
            List of event dictionaries
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM events WHERE 1=1"
            params = []

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)

            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)

            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)

            events = []
            for row in cursor.fetchall():
                event = dict(row)
                if event["raw_data"]:
                    event["raw_data"] = json.loads(event["raw_data"])
                events.append(event)

            return events

    def get_event_by_id(self, event_id: int) -> Optional[Dict]:
        """Get a specific event by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
            row = cursor.fetchone()

            if row:
                event = dict(row)
                if event["raw_data"]:
                    event["raw_data"] = json.loads(event["raw_data"])
                return event
            return None

    def get_recent_events(self, minutes: int = 60, limit: int = 100) -> List[Dict]:
        """Get events from the last N minutes."""
        start_time = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        return self.get_events(limit=limit, start_date=start_time)

    def get_event_counts_by_severity(self) -> Dict[str, int]:
        """Get count of events grouped by severity."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM events
                GROUP BY severity
            """
            )

            return {row["severity"]: row["count"] for row in cursor.fetchall()}

    def get_event_counts_by_type(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get count of events grouped by type."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT event_type, COUNT(*) as count
                FROM events
                GROUP BY event_type
                ORDER BY count DESC
                LIMIT ?
            """,
                (limit,),
            )

            return [(row["event_type"], row["count"]) for row in cursor.fetchall()]

    def get_events_timeline(
        self, hours: int = 24, interval_minutes: int = 50
    ) -> List[Tuple[str, int]]:
        """
        Get event counts over time.

        Args:
            hours: Number of hours to look back
            interval_minutes: Interval for grouping (in minutes)

        Returns:
            List of (timestamp, count) tuples
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            start_time = (datetime.now() - timedelta(hours=hours)).isoformat()

            cursor.execute(
                """
                SELECT 
                    strftime('%Y-%m-%d %H:%M', timestamp) as time_bucket,
                    COUNT(*) as count
                FROM events
                WHERE timestamp >= ?
                GROUP BY time_bucket
                ORDER BY time_bucket
            """,
                (start_time,),
            )

            return [(row["time_bucket"], row["count"]) for row in cursor.fetchall()]

    def get_alerts(self, acknowledged: bool = None, limit: int = 50) -> List[Dict]:
        """Get alerts with optional filtering."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT a.*, e.description as event_description, e.severity
                FROM alerts a
                LEFT JOIN events e ON a.event_id = e.id
                WHERE 1=1
            """
            params = []

            if acknowledged is not None:
                query += " AND a.acknowledged = ?"
                params.append(1 if acknowledged else 0)

            query += " ORDER BY a.triggered_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def acknowledge_alert(self, alert_id: int):
        """Mark an alert as acknowledged."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE alerts SET acknowledged = 1 WHERE id = ?
            """,
                (alert_id,),
            )

    def get_latest_system_stats(self, limit: int = 100) -> List[Dict]:
        """Get latest system statistics."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM system_stats 
                ORDER BY timestamp DESC 
                LIMIT ?
            """,
                (limit,),
            )

            return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_events(self, days: int = None):
        """
        Remove events older than specified days.

        Args:
            days: Number of days to keep (uses Settings.EVENT_RETENTION_DAYS if not specified)
        """
        days = days or Settings.EVENT_RETENTION_DAYS
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Delete old events
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_date,))
            deleted_events = cursor.rowcount

            # Delete orphaned alerts
            cursor.execute(
                """
                DELETE FROM alerts 
                WHERE event_id NOT IN (SELECT id FROM events)
            """
            )
            deleted_alerts = cursor.rowcount

            # Delete old stats
            cursor.execute(
                "DELETE FROM system_stats WHERE timestamp < ?", (cutoff_date,)
            )
            deleted_stats = cursor.rowcount

            logger.info(
                f"Cleanup: Removed {deleted_events} events, {deleted_alerts} alerts, {deleted_stats} stats"
            )

    def get_total_event_count(self) -> int:
        """Get total number of events in database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM events")
            return cursor.fetchone()["count"]

    def get_critical_event_count(self) -> int:
        """Get count of critical events."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) as count FROM events WHERE severity = 'Critical'
            """
            )
            return cursor.fetchone()["count"]

    def search_events(self, keyword: str, limit: int = 100) -> List[Dict]:
        """Search events by keyword in description."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM events 
                WHERE description LIKE ? OR event_type LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (f"%{keyword}%", f"%{keyword}%", limit),
            )

            events = []
            for row in cursor.fetchall():
                event = dict(row)
                if event["raw_data"]:
                    event["raw_data"] = json.loads(event["raw_data"])
                events.append(event)

            return events

    def clear_all_data(self):
        """Clear all events, alerts, and system stats from database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Delete all alerts
            cursor.execute("DELETE FROM alerts")
            deleted_alerts = cursor.rowcount

            # Delete all events
            cursor.execute("DELETE FROM events")
            deleted_events = cursor.rowcount

            # Delete all system stats
            cursor.execute("DELETE FROM system_stats")
            deleted_stats = cursor.rowcount

            # Reset autoincrement counters
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='events'")
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='system_stats'")

            logger.info(
                f"Cleared all data: {deleted_events} events, {deleted_alerts} alerts, {deleted_stats} stats"
            )
            return deleted_events, deleted_alerts, deleted_stats
