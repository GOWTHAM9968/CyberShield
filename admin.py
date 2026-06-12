import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("cybershield.db")

cursor = conn.cursor()

cursor.execute(
"""
INSERT INTO users
(username,email,password)
VALUES(?,?,?)
""",
(
"admin",
"admin@cybershield.com",
generate_password_hash("admin123")
)
)

conn.commit()
conn.close()

print("Admin Created")