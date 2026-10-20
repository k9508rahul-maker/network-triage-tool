import json
import os
import sqlite3
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "triage.db")


def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                total_packets INTEGER NOT NULL,
                unique_ips INTEGER NOT NULL,
                protocols_json TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                source_ip TEXT NOT NULL,
                finding TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                evidence TEXT NOT NULL,
                FOREIGN KEY (analysis_id)
                    REFERENCES analyses(id)
                    ON DELETE CASCADE
            )
        """)

        # Step 13.1: IP observations table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                role TEXT NOT NULL,
                packet_count INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (analysis_id)
                    REFERENCES analyses(id)
                    ON DELETE CASCADE
            )
        """)

        # Add status column to existing databases if needed
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(findings)"
            ).fetchall()
        }

        if "status" not in columns:
            conn.execute("""
                ALTER TABLE findings
                ADD COLUMN status TEXT NOT NULL DEFAULT 'Open'
            """)


def save_analysis(filename, result):
    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO analyses (
                filename, analyzed_at, total_packets,
                unique_ips, protocols_json
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            filename,
            datetime.now(timezone.utc).isoformat(),
            result["total_packets"],
            result["unique_ips"],
            json.dumps(result["protocols"]),
        ))

        # Get the newly created analysis ID
        analysis_id = cursor.lastrowid

        # Save findings
        for event in result["events"]:
            conn.execute("""
                INSERT INTO findings (
                    analysis_id, source_ip, finding,
                    severity, event_count, evidence
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                analysis_id,
                event["source"],
                event["finding"],
                event["severity"],
                event["count"],
                event.get("evidence", ""),
            ))

        # Step 13.3: Prepare IP observation records
        ip_rows = []

        for ip_address, count in result.get(
            "source_counts", {}
        ).items():
            ip_rows.append((
                analysis_id,
                ip_address,
                "Source",
                int(count),
            ))

        for ip_address, count in result.get(
            "destination_counts", {}
        ).items():
            ip_rows.append((
                analysis_id,
                ip_address,
                "Destination",
                int(count),
            ))

        # Insert IP observations into the database
        if ip_rows:
            conn.executemany("""
                INSERT INTO ip_observations (
                    analysis_id,
                    ip_address,
                    role,
                    packet_count
                )
                VALUES (?, ?, ?, ?)
            """, ip_rows)

        return analysis_id


def get_history():
    with get_connection() as conn:
        return conn.execute("""
            SELECT
                a.id,
                a.filename,
                a.analyzed_at,
                a.total_packets,
                a.unique_ips,
                COUNT(f.id) AS findings_count
            FROM analyses a
            LEFT JOIN findings f ON f.analysis_id = a.id
            GROUP BY a.id
            ORDER BY a.id DESC
            LIMIT 100
        """).fetchall()


def get_dashboard_stats():
    with get_connection() as conn:
        totals = conn.execute("""
            SELECT
                COALESCE(SUM(total_packets), 0) AS total_packets,
                COUNT(*) AS total_analyses
            FROM analyses
        """).fetchone()

        latest = conn.execute("""
            SELECT unique_ips
            FROM analyses
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        findings = conn.execute("""
            SELECT
                COUNT(*) AS total_findings,
                COALESCE(SUM(
                    CASE WHEN severity = 'High' THEN 1 ELSE 0 END
                ), 0) AS high_severity
            FROM findings
        """).fetchone()

        return {
            "total_packets": totals["total_packets"],
            "unique_ips": latest["unique_ips"] if latest else 0,
            "suspicious_events": findings["total_findings"],
            "high_severity": findings["high_severity"],
            "total_analyses": totals["total_analyses"],
        }


def get_analysis(analysis_id):
    with get_connection() as conn:
        analysis = conn.execute(
            "SELECT * FROM analyses WHERE id = ?",
            (analysis_id,)
        ).fetchone()

        if analysis is None:
            return None, []

        events = conn.execute("""
            SELECT source_ip, finding, severity, event_count, evidence
            FROM findings
            WHERE analysis_id = ?
            ORDER BY id
        """, (analysis_id,)).fetchall()

        return analysis, events


# Step 11.2: Protocol statistics for the latest 100 analyses
def get_protocol_totals():
    totals = {}

    with get_connection() as conn:
        rows = conn.execute("""
            SELECT protocols_json
            FROM analyses
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    for row in rows:
        try:
            protocols = json.loads(row["protocols_json"])
        except (ValueError, TypeError):
            continue

        if not isinstance(protocols, dict):
            continue

        for protocol, count in protocols.items():
            try:
                totals[protocol] = totals.get(protocol, 0) + int(count)
            except (ValueError, TypeError):
                continue

    return dict(sorted(totals.items()))


# Step 11.2: Latest analysis history
def get_recent_analyses(limit=5):
    with get_connection() as conn:
        return conn.execute("""
            SELECT
                a.id,
                a.filename,
                a.analyzed_at,
                a.total_packets,
                a.unique_ips,
                COUNT(f.id) AS findings_count
            FROM analyses a
            LEFT JOIN findings f ON f.analysis_id = a.id
            GROUP BY a.id
            ORDER BY a.id DESC
            LIMIT ?
        """, (limit,)).fetchall()


# Step 16.1: Traffic chart data for the latest 7 analyses
def get_traffic_chart_data():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT analyzed_at, total_packets
            FROM analyses
            ORDER BY id DESC
            LIMIT 7
        """).fetchall()

    return [
        {
            "label": str(row["analyzed_at"]),
            "packets": int(row["total_packets"] or 0),
        }
        for row in reversed(rows)
    ]


# Step 16.2: Severity summary for dashboard
def get_severity_summary():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT severity, COUNT(*) AS total
            FROM findings
            GROUP BY severity
        """).fetchall()

    summary = {"High": 0, "Medium": 0, "Low": 0}

    for row in rows:
        if row["severity"] in summary:
            summary[row["severity"]] = int(row["total"])

    return summary


# Alert status initialization
def init_alert_status():
    with get_connection() as conn:
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(findings)"
            ).fetchall()
        }

        if "status" not in columns:
            conn.execute("""
                ALTER TABLE findings
                ADD COLUMN status TEXT NOT NULL DEFAULT 'Open'
            """)


# Update finding status
def update_finding_status(finding_id, status):
    allowed_statuses = {
        "Open", "Investigating", "Resolved"
    }

    if status not in allowed_statuses:
        return False

    with get_connection() as conn:
        cursor = conn.execute("""
            UPDATE findings
            SET status = ?
            WHERE id = ?
        """, (status, finding_id))

        return cursor.rowcount > 0
