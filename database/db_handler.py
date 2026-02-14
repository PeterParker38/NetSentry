import sqlite3

DB = "netsentry.db"

def init_db():
    conn = sqlite3.connect(DB)
    with open("database/schema.sql") as f:
        conn.executescript(f.read())
    conn.close()
