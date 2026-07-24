import sqlite3

conn = sqlite3.connect("cybershield.db")
cursor = conn.cursor()

cursor.execute("SELECT id, username, email, password FROM users")

users = cursor.fetchall()

for user in users:
    print(user)

conn.close()