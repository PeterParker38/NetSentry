import sqlite3
from datetime import datetime, timedelta

DB = "netsentry.db"

def detect_port_scan(src_ip):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    time_limit = (datetime.now() - timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        SELECT COUNT(DISTINCT dst_port)
        FROM packets
        WHERE src_ip = ?
        AND timestamp > ?
    """, (src_ip, time_limit))

    count = cur.fetchone()[0]

    if count > 15:
        cur.execute("""
            INSERT INTO alerts (timestamp, message)
            VALUES (?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            f"⚠ Possible Port Scan from {src_ip}"
        ))

    conn.commit()
    conn.close()
