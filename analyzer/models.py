"""
SQLite database schema and query helpers.

Database file lives in the mounted data volume at /app/data/perf_analyzer.db
"""

import sqlite3
import json
import os

DB_DIR = os.environ.get('DATA_DIR', '/app/data')
DB_PATH = os.path.join(DB_DIR, 'perf_analyzer.db')


def get_db():
    """Get a database connection with row factory enabled."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS uploads (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cluster_id      TEXT NOT NULL,
            hostname        TEXT,
            upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            collection_timestamp TEXT,
            filename        TEXT NOT NULL,
            kernel_version  TEXT,
            cpu_info        TEXT,
            cpu_count       INTEGER,
            mem_total       TEXT,
            duration_seconds INTEGER,
            frequency_hz    INTEGER,
            total_samples   INTEGER,
            flamegraph_json TEXT,
            analysis_json   TEXT,
            metadata_json   TEXT,
            folded_json     TEXT,
            pid_folded_json TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_cluster_id
            ON uploads(cluster_id);

        CREATE INDEX IF NOT EXISTS idx_upload_timestamp
            ON uploads(upload_timestamp DESC);
    ''')
    _migrate_add_folded_json(conn)
    _migrate_add_pid_folded_json(conn)
    conn.commit()
    conn.close()


def _migrate_add_folded_json(conn):
    """Add folded_json column if it doesn't exist (handles upgrades from older DB)."""
    cursor = conn.execute("PRAGMA table_info(uploads)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'folded_json' not in columns:
        conn.execute('ALTER TABLE uploads ADD COLUMN folded_json TEXT')
        conn.commit()


def _migrate_add_pid_folded_json(conn):
    """Add pid_folded_json column if it doesn't exist."""
    cursor = conn.execute("PRAGMA table_info(uploads)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'pid_folded_json' not in columns:
        conn.execute('ALTER TABLE uploads ADD COLUMN pid_folded_json TEXT')
        conn.commit()


def insert_upload(cluster_id, hostname, collection_timestamp, filename,
                  kernel_version, cpu_info, cpu_count, mem_total,
                  duration_seconds, frequency_hz, total_samples,
                  flamegraph_json, analysis_json, metadata_json,
                  folded_json=None, pid_folded_json=None):
    """Insert a new upload record. Returns the new row ID."""
    conn = get_db()
    cursor = conn.execute('''
        INSERT INTO uploads (
            cluster_id, hostname, collection_timestamp, filename,
            kernel_version, cpu_info, cpu_count, mem_total,
            duration_seconds, frequency_hz, total_samples,
            flamegraph_json, analysis_json, metadata_json,
            folded_json, pid_folded_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        cluster_id, hostname, collection_timestamp, filename,
        kernel_version, cpu_info, cpu_count, mem_total,
        duration_seconds, frequency_hz, total_samples,
        json.dumps(flamegraph_json) if isinstance(flamegraph_json, dict) else flamegraph_json,
        json.dumps(analysis_json) if isinstance(analysis_json, dict) else analysis_json,
        json.dumps(metadata_json) if isinstance(metadata_json, dict) else metadata_json,
        json.dumps(folded_json) if isinstance(folded_json, dict) else folded_json,
        json.dumps(pid_folded_json) if isinstance(pid_folded_json, dict) else pid_folded_json,
    ))
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def get_all_uploads():
    """Return all uploads, newest first."""
    conn = get_db()
    rows = conn.execute('''
        SELECT id, cluster_id, hostname, upload_timestamp,
               collection_timestamp, filename, kernel_version,
               total_samples, duration_seconds, frequency_hz
        FROM uploads
        ORDER BY upload_timestamp DESC
    ''').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_cluster_ids():
    """Return distinct cluster IDs."""
    conn = get_db()
    rows = conn.execute('''
        SELECT DISTINCT cluster_id FROM uploads ORDER BY cluster_id
    ''').fetchall()
    conn.close()
    return [r['cluster_id'] for r in rows]


def get_uploads_by_cluster(cluster_id):
    """Return uploads for a specific cluster ID."""
    conn = get_db()
    rows = conn.execute('''
        SELECT id, cluster_id, hostname, upload_timestamp,
               collection_timestamp, filename, kernel_version,
               total_samples, duration_seconds, frequency_hz
        FROM uploads
        WHERE cluster_id = ?
        ORDER BY upload_timestamp DESC
    ''', (cluster_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_upload(upload_id):
    """Return a single upload by ID, including all JSON fields."""
    conn = get_db()
    row = conn.execute('''
        SELECT * FROM uploads WHERE id = ?
    ''', (upload_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    result = dict(row)
    for field in ('flamegraph_json', 'analysis_json', 'metadata_json', 'folded_json', 'pid_folded_json'):
        if result.get(field) and isinstance(result[field], str):
            try:
                result[field] = json.loads(result[field])
            except (json.JSONDecodeError, TypeError):
                pass
    return result


def delete_upload(upload_id):
    """Delete an upload record by ID."""
    conn = get_db()
    conn.execute('DELETE FROM uploads WHERE id = ?', (upload_id,))
    conn.commit()
    conn.close()
