import sqlite3

conn = sqlite3.connect("cybershield.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT UNIQUE,
    password TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS incidents(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_name TEXT,
    severity TEXT,
    description TEXT
)
""")

conn.commit()
conn.close()

print("CyberShield Database Ready")