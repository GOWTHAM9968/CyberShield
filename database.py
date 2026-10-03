import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "cybershield.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db_connection():
    """
    Create and return a SQLite database connection.

    sqlite3.Row allows accessing columns by name:
        user["email"]
        user["password"]
        user["role"]
    """

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    # Enable foreign-key support
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():
    """
    Create all CyberShield database tables.
    """

    connection = get_db_connection()

    cursor = connection.cursor()

    # ========================================================
    # USERS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            email TEXT NOT NULL UNIQUE,

            password TEXT NOT NULL,

            role TEXT NOT NULL DEFAULT 'user',

            is_active INTEGER NOT NULL DEFAULT 1,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ========================================================
    # INCIDENTS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            title TEXT NOT NULL,

            description TEXT NOT NULL,

            severity TEXT NOT NULL DEFAULT 'Medium',

            status TEXT NOT NULL DEFAULT 'Open',

            category TEXT DEFAULT 'General',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # EVIDENCE TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id INTEGER,

            filename TEXT NOT NULL,

            original_filename TEXT,

            file_path TEXT,

            file_size INTEGER DEFAULT 0,

            md5 TEXT,

            sha1 TEXT,

            sha256 TEXT,

            uploaded_by INTEGER,

            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (incident_id)
                REFERENCES incidents(id)
                ON DELETE CASCADE,

            FOREIGN KEY (uploaded_by)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # MALWARE SCANS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malware_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            filename TEXT NOT NULL,

            file_size INTEGER DEFAULT 0,

            md5 TEXT,

            sha1 TEXT,

            sha256 TEXT,

            scan_result TEXT DEFAULT 'Analysis Only',

            risk_level TEXT DEFAULT 'Unknown',

            scanner TEXT DEFAULT 'CyberShield',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # NETWORK SCANS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            target TEXT NOT NULL,

            ports TEXT,

            open_ports TEXT,

            status TEXT DEFAULT 'Completed',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # URL SCANS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            url TEXT NOT NULL,

            risk_level TEXT DEFAULT 'Unknown',

            score INTEGER DEFAULT 0,

            result TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # HASH CHECKS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hash_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            hash_value TEXT NOT NULL,

            hash_type TEXT DEFAULT 'Unknown',

            result TEXT DEFAULT 'Unknown',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # THREAT INTELLIGENCE TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            indicator TEXT NOT NULL,

            indicator_type TEXT DEFAULT 'Unknown',

            threat_level TEXT DEFAULT 'Unknown',

            source TEXT DEFAULT 'CyberShield',

            result TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # IP LOOKUPS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_lookups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            ip_address TEXT NOT NULL,

            result TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # RISK ASSESSMENTS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            asset TEXT NOT NULL,

            risk_level TEXT DEFAULT 'Medium',

            score INTEGER DEFAULT 0,

            recommendations TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # LOGS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            action TEXT NOT NULL,

            category TEXT DEFAULT 'System',

            severity TEXT DEFAULT 'INFO',

            ip_address TEXT,

            details TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # PASSWORD RESET / SECURITY EVENTS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            event_type TEXT NOT NULL,

            description TEXT,

            ip_address TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        )
    """)

    # ========================================================
    # SETTINGS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER NOT NULL UNIQUE,

            email_alerts INTEGER DEFAULT 1,

            security_alerts INTEGER DEFAULT 1,

            login_alerts INTEGER DEFAULT 1,

            dark_mode INTEGER DEFAULT 1,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
    """)

    # ========================================================
    # CREATE DEFAULT ADMIN
    # ========================================================

    admin_email = "admin@cybershield.com"

    existing_admin = cursor.execute(
        """
        SELECT id
        FROM users
        WHERE email = ?
        LIMIT 1
        """,
        (admin_email,)
    ).fetchone()

    if existing_admin is None:

        admin_password = generate_password_hash("Admin@123")

        cursor.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                password,
                role,
                is_active
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "CyberShield Administrator",
                admin_email,
                admin_password,
                "admin",
                1
            )
        )

        print("Default admin account created.")

    # ========================================================
    # CREATE INDEXES
    # ========================================================

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_email
        ON users(email)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_user
        ON incidents(user_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_status
        ON incidents(status)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_user
        ON logs(user_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_created
        ON logs(created_at)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_malware_user
        ON malware_scans(user_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_network_user
        ON network_scans(user_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_url_user
        ON url_scans(user_id)
    """)

    # ========================================================
    # SAVE CHANGES
    # ========================================================

    connection.commit()

    connection.close()

    print("CyberShield database initialized successfully.")
    print(f"Database location: {DATABASE_PATH}")


# ============================================================
# ADD LOG
# ============================================================

def add_log(
    user_id=None,
    action="System Action",
    category="System",
    severity="INFO",
    ip_address=None,
    details=None
):
    """
    Add an activity/security log.
    """

    connection = get_db_connection()

    connection.execute(
        """
        INSERT INTO logs
        (
            user_id,
            action,
            category,
            severity,
            ip_address,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            category,
            severity,
            ip_address,
            details
        )
    )

    connection.commit()

    connection.close()


# ============================================================
# CREATE USER
# ============================================================

def create_user(name, email, password, role="user"):
    """
    Create a new user.

    Returns:
        True  -> successfully created
        False -> email already exists
    """

    connection = get_db_connection()

    try:

        hashed_password = generate_password_hash(password)

        connection.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                password,
                role
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                email.lower().strip(),
                hashed_password,
                role
            )
        )

        connection.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    finally:

        connection.close()


# ============================================================
# GET USER BY EMAIL
# ============================================================

def get_user_by_email(email):
    """
    Find one user using their email.
    """

    connection = get_db_connection()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        LIMIT 1
        """,
        (email.lower().strip(),)
    ).fetchone()

    connection.close()

    return user


# ============================================================
# GET USER BY ID
# ============================================================

def get_user_by_id(user_id):
    """
    Find one user using their ID.
    """

    connection = get_db_connection()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        LIMIT 1
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    return user


# ============================================================
# INITIALIZE DATABASE WHEN FILE IS RUN DIRECTLY
# ============================================================

if __name__ == "__main__":
    init_database()