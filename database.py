import sqlite3

conn = sqlite3.connect("cybershield.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS incidents(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL
)
""")

conn.commit()
conn.close()

print("Database Created Successfully")