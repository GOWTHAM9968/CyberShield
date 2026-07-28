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

cursor.execute("""
CREATE TABLE IF NOT EXISTS evidence(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    filesize TEXT,
    uploaded_by TEXT,
    upload_time TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS malware_scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    status TEXT,
    scan_date TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS network_scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    host TEXT,
    ip TEXT,
    status TEXT,
    ports TEXT,
    services TEXT,
    scan_time TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT,
    severity TEXT,
    source TEXT,
    timestamp TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS activity_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    ip_address TEXT,
    timestamp TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS evidence(

id INTEGER PRIMARY KEY AUTOINCREMENT,

filename TEXT,

md5 TEXT,

sha1 TEXT,

sha256 TEXT,

filesize TEXT,

uploaded_by TEXT,

upload_time TEXT

)""")
conn.commit()
conn.close()

print("Database Created Successfully")