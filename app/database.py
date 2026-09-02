import sqlite3
from datetime import datetime

DB_NAME = "scans.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            content_source TEXT,
            prompt TEXT,
            is_threat BOOLEAN,
            reason TEXT,
            owasp TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_scan(prompt: str, content_source: str, is_threat: bool, reason: str, owasp: str = None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_logs (timestamp, content_source, prompt, is_threat, reason, owasp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), content_source, prompt, is_threat, reason, owasp))
    conn.commit()
    conn.close()