import os
import sqlite3
import hashlib
import socket
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_file
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.pdfgen import canvas

# ==========================================
# 1. APP CONFIGURATION
# ==========================================
app = Flask(__name__)
app.secret_key = "CyberShield_AI_Secret_Key_Super_Secure"

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ==========================================
# 2. FLASK-MAIL CONFIGURATION
# ==========================================
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "YOUR_GMAIL@gmail.com"  # Replace with your email
app.config["MAIL_PASSWORD"] = "YOUR_GOOGLE_APP_PASSWORD" # Replace with App Password
app.config["MAIL_DEFAULT_SENDER"] = "YOUR_GMAIL@gmail.com"

mail = Mail(app)

# ==========================================
# 3. FLASK-LOGIN CONFIGURATION
# ==========================================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# ==========================================
# 4. DATABASE CONFIGURATION
# ==========================================
DATABASE = "cybershield.db"

def get_db_connection():
    """Establishes and returns a database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes database tables if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            incident_name TEXT,
            severity TEXT,
            description TEXT,
            status TEXT DEFAULT 'OPEN',
            date TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malware (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            hash TEXT,
            result TEXT,
            date TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            date TEXT
        )
    """)
    conn.commit()
    conn.close()

# Initialize tables on startup
init_db()

# ==========================================
# 5. MODELS & HELPERS
# ==========================================
class User(UserMixin):
    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user["id"], user["username"], user["email"], user["password"])
    return None

def add_log(user, action):
    """Helper to log user activities."""
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO logs (user, action, date) VALUES (?, ?, ?)",
            (user, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Logging error: {e}")

def send_alert_email(subject, recipient, body):
    """Helper to send email alerts safely."""
    try:
        msg = Message(subject=subject, recipients=[recipient])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print(f"Mail Error: {e}")

def generate_hash(file):
    """Helper to generate SHA256 hash for a file."""
    sha256 = hashlib.sha256()
    while True:
        data = file.read(4096)
        if not data:
            break
        sha256.update(data)
    file.seek(0) # Reset file pointer after reading
    return sha256.hexdigest()

# ==========================================
# 6. AUTHENTICATION ROUTES
# ==========================================
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()
        existing_user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        
        if existing_user:
            conn.close()
            flash("Email is already registered. Please log in.", "warning")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        try:
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )
            conn.commit()
            flash("Registration Successful! Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash("An error occurred during registration.", "danger")
            print(f"DB Error: {e}")
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()
        user_data = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        if user_data and check_password_hash(user_data["password"], password):
            user = User(user_data["id"], user_data["username"], user_data["email"], user_data["password"])
            login_user(user)
            add_log(user.username, "Login Successful")

            # Login Email Alert
            body = f"Hello {user.username},\n\nA successful login was detected at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.\nIf this wasn't you, please change your password immediately.\n\nCyberShield Security"
            send_alert_email("CyberShield Login Alert", user.email, body)

            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    add_log(current_user.username, "Logout")
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

# ==========================================
# 7. DASHBOARD & REPORTS
# ==========================================
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db_connection()
    try:
        total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        active_threats = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity='High' OR severity='Critical'").fetchone()[0]
        recent_incidents = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 5").fetchall()
        total_malware = conn.execute("SELECT COUNT(*) FROM malware").fetchone()[0]
    except Exception as e:
        total_incidents, active_threats, recent_incidents, total_malware = 0, 0, [], 0
        print(f"Dashboard Error: {e}")
    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        username=current_user.username,
        total_incidents=total_incidents,
        active_threats=active_threats,
        recent_incidents=recent_incidents,
        total_malware=total_malware
    )

@app.route("/report", methods=["GET", "POST"])
@login_required
def report_incident():
    if request.method == "POST":
        incident_name = request.form.get("incident_name", "Unknown Incident")
        severity = request.form.get("severity", "Low")
        description = request.form.get("description", "")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO incidents (user, incident_name, severity, description, date) VALUES (?, ?, ?, ?, ?)",
                (current_user.username, incident_name, severity, description, current_time)
            )
            conn.commit()
            add_log(current_user.username, f"Reported Incident: {incident_name}")

            # Incident Email Alert
            body = f"CyberShield Security Alert\n\nNew Incident Reported by {current_user.username}\nIncident: {incident_name}\nSeverity: {severity}\nTime: {current_time}\nDescription:\n{description}"
            send_alert_email("🚨 CyberShield Incident Alert", current_user.email, body)

            flash("Incident Submitted Successfully", "success")
        except Exception as e:
            flash("Failed to report incident.", "danger")
            print(f"Incident Error: {e}")
        finally:
            conn.close()
            
        return redirect(url_for("dashboard"))

    return render_template("report_incident.html")

@app.route("/reports")
@login_required
def reports():
    conn = get_db_connection()
    incidents = conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("reports.html", incidents=incidents)

@app.route("/download_report/<int:incident_id>")
@login_required
def download_report(incident_id):
    conn = get_db_connection()
    incident = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()

    if not incident:
        flash("Incident Not Found", "danger")
        return redirect(url_for("reports"))

    filename = f"Incident_{incident_id}.pdf"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    
    # Generate PDF
    c = canvas.Canvas(filepath)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(70, 800, "CyberShield Incident Report")
    
    c.setFont("Helvetica", 12)
    c.drawString(70, 760, f"Incident ID : {incident['id']}")
    c.drawString(70, 730, f"Reported By : {incident['user']}")
    c.drawString(70, 700, f"Incident : {incident['incident_name']}")
    c.drawString(70, 670, f"Severity : {incident['severity']}")
    c.drawString(70, 640, f"Date : {incident['date']}")
    
    c.drawString(70, 600, "Description :")
    text = c.beginText(70, 580)
    text.textLines(incident["description"] if incident["description"] else "No description provided.")
    c.drawText(text)
    c.save()

    return send_file(filepath, as_attachment=True)

@app.route("/delete_incident/<int:incident_id>")
@login_required
def delete_incident(incident_id):
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
        conn.commit()
        add_log(current_user.username, f"Deleted incident #{incident_id}")
        flash("Incident Deleted Successfully", "success")
    except Exception as e:
        flash("Error deleting incident.", "danger")
        print(f"Delete Error: {e}")
    finally:
        conn.close()
    return redirect(url_for("reports"))

# ==========================================
# 8. ADMIN DASHBOARD & LOGS
# ==========================================
@app.route("/admin")
@login_required
def admin_dashboard():
    conn = get_db_connection()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    users = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    conn.close()

    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=total_users,
        total_incidents=total_incidents
    )

@app.route("/logs")
@login_required
def logs():
    conn = get_db_connection()
    logs_data = conn.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("logs.html", logs=logs_data)

# ==========================================
# 9. CYBERSECURITY TOOLS
# ==========================================
@app.route("/assistant", methods=["GET", "POST"])
@login_required
def assistant():
    answer = ""
    if request.method == "POST":
        question = request.form.get("question", "").lower()
        if "password" in question:
            answer = "Use a strong password with at least 12 characters, mixing uppercase, lowercase, numbers, and symbols. Enable MFA."
        elif "phishing" in question:
            answer = "Verify the sender's email address, inspect URLs by hovering before clicking, and never open unexpected attachments."
        elif "malware" in question:
            answer = "Keep your OS updated, use reputable antivirus software, and avoid pirated software."
        elif "ransomware" in question:
            answer = "Maintain secure offline backups (3-2-1 rule), keep systems patched, and disable unnecessary remote desktop protocols."
        elif "sql injection" in question:
            answer = "Always use parameterized SQL queries (Prepared Statements) and validate/sanitize all user inputs."
        elif "xss" in question:
            answer = "Escape output, validate user input, and implement a strong Content Security Policy (CSP)."
        else:
            answer = "No specific match found in the knowledge base. Please follow general cybersecurity best practices."
    
    return render_template("assistant.html", answer=answer)

@app.route("/risk")
@login_required
def risk():
    return render_template("risk.html")

@app.route("/url_scan", methods=["GET", "POST"])
@login_required
def url_scan():
    result = ""
    if request.method == "POST":
        url = request.form["url"].lower()
        suspicious_keywords = ["bit.ly", "tinyurl", "@", "free", "login", "verify", "update", "bank", "secure"]
        score = sum(1 for item in suspicious_keywords if item in url)

        if score >= 3:
            result = "High Risk URL"
        elif score >= 1:
            result = "Suspicious URL"
        else:
            result = "Looks Safe"
            
    return render_template("url_scan.html", result=result)

@app.route("/ip_lookup", methods=["GET", "POST"])
@login_required
def ip_lookup():
    result = None
    if request.method == "POST":
        ip = request.form["ip"]
        # In a real app, query an API like ipinfo.io here
        result = {
            "ip": ip,
            "country": "Unknown (Demo Mode)",
            "city": "Unknown (Demo Mode)",
            "status": "Lookup API Not Connected"
        }
    return render_template("ip_lookup.html", result=result)

@app.route("/hash_check", methods=["GET", "POST"])
@login_required
def hash_check():
    result = ""
    if request.method == "POST":
        hash_value = request.form["hash"].strip()
        length = len(hash_value)
        if length == 32:
            result = "MD5 Hash format detected."
        elif length == 40:
            result = "SHA1 Hash format detected."
        elif length == 64:
            result = "SHA256 Hash format detected."
        else:
            result = "Unknown Hash format. Invalid length."
    return render_template("hash_check.html", result=result)

@app.route("/threat_intelligence")
@login_required
def threat_intelligence():
    threats = [
        {"name": "Emotet", "severity": "Critical", "status": "Active"},
        {"name": "LockBit", "severity": "High", "status": "Active"},
        {"name": "BlackCat", "severity": "Critical", "status": "Monitoring"},
        {"name": "Mirai Botnet", "severity": "Medium", "status": "Blocked"}
    ]
    return render_template("threat_intelligence.html", threats=threats)

@app.route("/network_scanner", methods=["GET", "POST"])
@login_required
def network_scanner():
    results = []
    if request.method == "POST":
        target = request.form.get("target")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) # Short timeout for speed
            status = sock.connect_ex((target, port))
            if status == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                results.append({"port": port, "service": service, "status": "Open"})
            sock.close()
    return render_template("network_scanner.html", results=results)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        if 'file' not in request.files:
            flash("No file part", "danger")
            return redirect(request.url)
            
        file = request.files["file"]
        if file.filename == '':
            flash("No selected file", "danger")
            return redirect(request.url)

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        # Hash analysis
        with open(filepath, "rb") as f:
            hash_value = generate_hash(f)

        # Simple file-extension heuristic
        result = "Suspicious" if file.filename.lower().endswith((".exe", ".bat", ".dll", ".sh")) else "Safe"

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO malware (filename, hash, result, date) VALUES (?, ?, ?, ?)",
                (file.filename, hash_value, result, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            add_log(current_user.username, f"Scanned file: {file.filename}")
            flash(f"File Scanned. Result: {result}", "info")
        except Exception as e:
            flash("Error saving scan record.", "danger")
            print(f"Malware DB Error: {e}")
        finally:
            conn.close()

        return redirect(url_for('upload'))

    return render_template("upload.html")

# ==========================================
# 10. USER PROFILE
# ==========================================
@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    new_password = request.form.get("password")
    if new_password:
        hashed_pw = generate_password_hash(new_password)
        conn = get_db_connection()
        try:
            conn.execute("UPDATE users SET password=? WHERE id=?", (hashed_pw, current_user.id))
            conn.commit()
            add_log(current_user.username, "Password Changed")
            flash("Password updated successfully.", "success")
        except Exception as e:
            flash("Error updating password.", "danger")
            print(f"Password Update Error: {e}")
        finally:
            conn.close()
    return redirect(url_for("profile"))

# ==========================================
# START APPLICATION
# ==========================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)