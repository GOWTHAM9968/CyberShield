import sqlite3

conn = sqlite3.connect("cybershield.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT,
    password TEXT
)
""")

conn.commit()
conn.close()

print("Database Created Successfully")