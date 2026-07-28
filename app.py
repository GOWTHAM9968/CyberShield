from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file,
    flash,
    url_for
)

import sqlite3
import os
from datetime import datetime
from functools import wraps

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask_mail import Mail, Message
from reportlab.pdfgen import canvas


# ==========================================
# Flask App
# ==========================================

app = Flask(__name__)
app.secret_key = "cybershield_secret_key"


# ==========================================
# Mail Configuration
# ==========================================

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "YOUR_GMAIL@gmail.com"
app.config["MAIL_PASSWORD"] = "YOUR_GOOGLE_APP_PASSWORD"
app.config["MAIL_DEFAULT_SENDER"] = "YOUR_GMAIL@gmail.com"

mail = Mail(app)


# ==========================================
# Database
# ==========================================

DATABASE = "cybershield.db"


def get_db_connection():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    return conn


# ==========================================
# Login Required Decorator
# ==========================================

def login_required(func):

    @wraps(func)

    def wrapper(*args, **kwargs):

        if "user" not in session:

            return redirect("/login")

        return func(*args, **kwargs)

    return wrapper


# ==========================================
# Home
# ==========================================

@app.route("/")
def home():

    return render_template("index.html")


# ==========================================
# Register
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        existing = cursor.fetchone()

        if existing:

            conn.close()

            flash("Email already registered.")

            return redirect("/register")

        hashed_password = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users
            (username,email,password)
            VALUES(?,?,?)
            """,
            (
                username,
                email,
                hashed_password
            )
        )

        conn.commit()

        conn.close()

        flash("Registration Successful")

        return redirect("/login")

    return render_template("register.html")


# ==========================================
# Login
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        user = cursor.fetchone()

        conn.close()

        if user is None:

            flash("Email not found")

            return redirect("/login")

        if not check_password_hash(
            user["password"],
            password
        ):

            flash("Incorrect Password")

            return redirect("/login")

        session["user"] = user["username"]
        session["email"] = user["email"]

        # Login Email Alert
        try:

            msg = Message(
                subject="CyberShield Login Alert",
                recipients=[user["email"]]
            )

            msg.body = f"""
Hello {user['username']},

A successful login was detected.

Time :
{datetime.now()}

If this wasn't you,
please change your password immediately.

CyberShield Security
"""

            mail.send(msg)

        except Exception as e:

            print("Mail Error:", e)

        return redirect("/dashboard")

    return render_template("login.html")


# ==========================================
# Logout
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    flash("Logged Out Successfully")

    return redirect("/")


# ==========================================
# Helper
# ==========================================

def send_security_email(subject, recipient, body):

    try:

        msg = Message(
            subject=subject,
            recipients=[recipient]
        )

        msg.body = body

        mail.send(msg)

    except Exception as e:

        print("Mail Error:", e)

# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]
    except:
        total_incidents = 0

    try:
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE severity='High'
            """
        )
        active_threats = cursor.fetchone()[0]
    except:
        active_threats = 0

    try:
        cursor.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY id DESC
            LIMIT 5
            """
        )
        recent_incidents = cursor.fetchall()
    except:
        recent_incidents = []

    conn.close()

    return render_template(
        "dashboard.html",
        username=session["user"],
        total_incidents=total_incidents,
        active_threats=active_threats,
        recent_incidents=recent_incidents
    )


# ==========================================
# REPORT INCIDENT
# ==========================================

@app.route("/report", methods=["GET", "POST"])
@login_required
def report():

    if request.method == "POST":

        incident_name = request.form["incident_name"]
        severity = request.form["severity"]
        description = request.form["description"]

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO incidents
            (incident_name,severity,description)
            VALUES(?,?,?)
            """,
            (
                incident_name,
                severity,
                description
            )
        )

        conn.commit()
        conn.close()

        # ================= EMAIL ALERT =================

        try:

            msg = Message(
                subject="🚨 CyberShield Incident Alert",
                recipients=[session["email"]]
            )

            msg.body = f"""
CyberShield Security Alert

New Incident Reported

Incident : {incident_name}

Severity : {severity}

Description :

{description}

Reported By :
{session['user']}

Time :
{datetime.now()}
"""

            mail.send(msg)

        except Exception as e:

            print("Mail Error :", e)

        flash("Incident Submitted Successfully")

        return redirect("/dashboard")

    return render_template("report_incident.html")


# ==========================================
# REPORTS
# ==========================================

@app.route("/reports")
@login_required
def reports():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM incidents
        ORDER BY id DESC
        """
    )

    incidents = cursor.fetchall()

    conn.close()

    return render_template(
        "reports.html",
        incidents=incidents
    )


# ==========================================
# DOWNLOAD PDF
# ==========================================

@app.route("/download_report/<int:incident_id>")
@login_required
def download_report(incident_id):

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM incidents
        WHERE id=?
        """,
        (incident_id,)
    )

    incident = cursor.fetchone()

    conn.close()

    if incident is None:

        flash("Incident Not Found")

        return redirect("/reports")

    filename = f"Incident_{incident_id}.pdf"

    c = canvas.Canvas(filename)

    c.setFont("Helvetica-Bold",18)
    c.drawString(70,800,"CyberShield Incident Report")

    c.setFont("Helvetica",12)

    c.drawString(70,760,f"Incident ID : {incident['id']}")
    c.drawString(70,730,f"Incident : {incident['incident_name']}")
    c.drawString(70,700,f"Severity : {incident['severity']}")

    c.drawString(70,670,"Description :")

    text = c.beginText(70,640)
    text.textLines(incident["description"])
    c.drawText(text)

    c.save()

    return send_file(
        filename,
        as_attachment=True
    )


# ==========================================
# DELETE INCIDENT
# ==========================================

@app.route("/delete_incident/<int:incident_id>")
@login_required
def delete_incident(incident_id):

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM incidents
        WHERE id=?
        """,
        (incident_id,)
    )

    conn.commit()

    conn.close()

    flash("Incident Deleted Successfully")

    return redirect("/reports")


# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@login_required
def admin_dashboard():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM users"
    )
    total_users = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM incidents"
    )
    total_incidents = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT *
        FROM users
        ORDER BY id DESC
        """
    )

    users = cursor.fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=total_users,
        total_incidents=total_incidents
    )
    
# ==========================================
# AI ASSISTANT
# ==========================================

@app.route("/assistant", methods=["GET", "POST"])
@login_required
def assistant():

    answer = ""

    if request.method == "POST":

        question = request.form["question"].lower()

        if "password" in question:
            answer = "Use a strong password with at least 12 characters and enable Multi-Factor Authentication."

        elif "phishing" in question:
            answer = "Verify the sender, inspect URLs carefully, and never open unknown attachments."

        elif "malware" in question:
            answer = "Keep your operating system updated, use antivirus software, and avoid downloading files from untrusted sources."

        elif "ransomware" in question:
            answer = "Maintain offline backups, keep systems patched, and never enable unknown macros."

        elif "wifi" in question:
            answer = "Use WPA3 or WPA2 encryption with a strong password."

        elif "sql injection" in question:
            answer = "Use parameterized SQL queries and validate all user input."

        elif "xss" in question:
            answer = "Escape output, validate input, and use Content Security Policy."

        else:
            answer = "No specific answer found. Please follow cybersecurity best practices."

    return render_template(
        "assistant.html",
        answer=answer
    )


# ==========================================
# RISK ASSESSMENT
# ==========================================

@app.route("/risk")
@login_required
def risk():

    return render_template("risk.html")


# ==========================================
# URL SCANNER
# ==========================================

@app.route("/url_scan", methods=["GET", "POST"])
@login_required
def url_scan():

    result = ""

    if request.method == "POST":

        url = request.form["url"]

        suspicious = [
            "bit.ly",
            "tinyurl",
            "@",
            "free",
            "login",
            "verify",
            "update",
            "bank",
            "secure"
        ]

        score = 0

        for item in suspicious:

            if item.lower() in url.lower():
                score += 1

        if score >= 3:

            result = "High Risk URL"

        elif score == 2:

            result = "Suspicious URL"

        else:

            result = "Looks Safe"

    return render_template(
        "url_scan.html",
        result=result
    )


# ==========================================
# IP LOOKUP
# ==========================================

@app.route("/ip_lookup", methods=["GET", "POST"])
@login_required
def ip_lookup():

    result = None

    if request.method == "POST":

        ip = request.form["ip"]

        result = {
            "ip": ip,
            "country": "Unknown",
            "city": "Unknown",
            "status": "Demo Mode"
        }

    return render_template(
        "ip_lookup.html",
        result=result
    )


# ==========================================
# HASH CHECKER
# ==========================================

@app.route("/hash_check", methods=["GET", "POST"])
@login_required
def hash_check():

    result = ""

    if request.method == "POST":

        hash_value = request.form["hash"]

        if len(hash_value) == 32:
            result = "MD5 Hash"

        elif len(hash_value) == 40:
            result = "SHA1 Hash"

        elif len(hash_value) == 64:
            result = "SHA256 Hash"

        else:
            result = "Unknown Hash"

    return render_template(
        "hash_check.html",
        result=result
    )


# ==========================================
# THREAT INTELLIGENCE
# ==========================================

@app.route("/threat_intelligence")
@login_required
def threat_intelligence():

    threats = [

        {
            "name": "Emotet",
            "severity": "Critical",
            "status": "Active"
        },

        {
            "name": "LockBit",
            "severity": "High",
            "status": "Active"
        },

        {
            "name": "BlackCat",
            "severity": "Critical",
            "status": "Monitoring"
        },

        {
            "name": "Mirai Botnet",
            "severity": "Medium",
            "status": "Blocked"
        }

    ]

    return render_template(
        "threat_intelligence.html",
        threats=threats
    )


# ==========================================
# NETWORK SCANNER (DAY 19)
# ==========================================

import socket

@app.route("/network_scanner", methods=["GET", "POST"])
@login_required
def network_scanner():

    results = []

    if request.method == "POST":

        target = request.form["target"]

        common_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            139,
            143,
            443,
            445,
            3389
        ]

        for port in common_ports:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(0.5)

            status = sock.connect_ex((target, port))

            if status == 0:

                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"

                results.append({
                    "port": port,
                    "service": service,
                    "status": "Open"
                })

            sock.close()

    return render_template(
        "network_scanner.html",
        results=results
    )

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from flask_mail import Mail, Message

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from datetime import datetime
import sqlite3
import hashlib
import os


# =========================
# APP CONFIG
# =========================

app = Flask(__name__)

app.secret_key = "CyberShield_AI_Secret_Key"


UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Email Configuration

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True

app.config["MAIL_USERNAME"] = "your_email@gmail.com"
app.config["MAIL_PASSWORD"] = "your_app_password"


mail = Mail(app)



# =========================
# LOGIN CONFIG
# =========================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"



# =========================
# DATABASE
# =========================


def db():

    conn = sqlite3.connect("cyber.db")

    conn.row_factory = sqlite3.Row

    return conn



def create_tables():

    conn=db()

    cursor=conn.cursor()


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    email TEXT,

    password TEXT

    )
    """)



    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user TEXT,

    title TEXT,

    description TEXT,

    status TEXT,

    date TEXT

    )
    """)



    cursor.execute("""
    CREATE TABLE IF NOT EXISTS malware(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    filename TEXT,

    hash TEXT,

    result TEXT,

    date TEXT

    )
    """)



    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user TEXT,

    action TEXT,

    date TEXT

    )
    """)


    conn.commit()

    conn.close()



create_tables()



# =========================
# USER MODEL
# =========================


class User(UserMixin):

    def __init__(self,id,username,email,password):

        self.id=id

        self.username=username

        self.email=email

        self.password=password



@login_manager.user_loader

def load_user(user_id):

    conn=db()

    user=conn.execute(

    "SELECT * FROM users WHERE id=?",

    (user_id,)

    ).fetchone()


    conn.close()


    if user:

        return User(

        user["id"],

        user["username"],

        user["email"],

        user["password"]

        )



# =========================
# ACTIVITY LOG
# =========================


def add_log(user,action):

    conn=db()

    conn.execute(

    """

    INSERT INTO logs(user,action,date)

    VALUES(?,?,?)

    """,

    (

    user,

    action,

    datetime.now()

    )

    )

    conn.commit()

    conn.close()



# =========================
# HASH GENERATOR
# =========================


def generate_hash(file):

    sha256=hashlib.sha256()


    while True:

        data=file.read(4096)

        if not data:

            break


        sha256.update(data)


    return sha256.hexdigest()



# =========================
# HOME
# =========================


@app.route("/")

def home():

    return redirect(url_for("login"))



# =========================
# REGISTER
# =========================


@app.route("/register",methods=["GET","POST"])

def register():


    if request.method=="POST":


        username=request.form["username"]

        email=request.form["email"]

        password=generate_password_hash(
            request.form["password"]
        )


        conn=db()


        conn.execute(

        """

        INSERT INTO users(username,email,password)

        VALUES(?,?,?)

        """,

        (

        username,

        email,

        password

        )

        )


        conn.commit()

        conn.close()


        flash("Account Created")

        return redirect("/login")


    return render_template("register.html")



# =========================
# LOGIN
# =========================


@app.route("/login",methods=["GET","POST"])

def login():


    if request.method=="POST":


        email=request.form["email"]

        password=request.form["password"]



        conn=db()


        user=conn.execute(

        "SELECT * FROM users WHERE email=?",

        (email,)

        ).fetchone()


        conn.close()



        if user and check_password_hash(

            user["password"],

            password

        ):


            login_user(

            User(

            user["id"],

            user["username"],

            user["email"],

            user["password"]

            )

            )


            add_log(

            user["username"],

            "Login Successful"

            )


            return redirect("/dashboard")



        flash("Invalid Login")


    return render_template("login.html")



# =========================
# LOGOUT
# =========================


@app.route("/logout")

@login_required

def logout():

    add_log(

    current_user.username,

    "Logout"

    )

    logout_user()

    return redirect("/login")



# =========================
# DASHBOARD SIEM
# =========================


@app.route("/dashboard")

@login_required

def dashboard():


    conn=db()


    users=conn.execute(

    "SELECT COUNT(*) FROM users"

    ).fetchone()[0]


    incidents=conn.execute(

    "SELECT COUNT(*) FROM incidents"

    ).fetchone()[0]


    malware=conn.execute(

    "SELECT COUNT(*) FROM malware"

    ).fetchone()[0]


    conn.close()



    return render_template(

    "dashboard.html",

    users=users,

    incidents=incidents,

    malware=malware

    )



# =========================
# INCIDENT REPORT
# =========================


@app.route("/incident",methods=["POST"])

@login_required

def incident():


    title=request.form["title"]

    description=request.form["description"]


    conn=db()


    conn.execute(

    """

    INSERT INTO incidents

    VALUES(NULL,?,?,?,?,?)

    """,

    (

    current_user.username,

    title,

    description,

    "OPEN",

    datetime.now()

    )

    )


    conn.commit()

    conn.close()



    add_log(

    current_user.username,

    "Incident Report Created"

    )


    return redirect("/dashboard")



# =========================
# MALWARE UPLOAD
# =========================


@app.route("/upload",methods=["GET","POST"])

@login_required

def upload():


    if request.method=="POST":


        file=request.files["file"]


        path=os.path.join(

        UPLOAD_FOLDER,

        file.filename

        )


        file.save(path)



        with open(path,"rb") as f:

            hash_value=generate_hash(f)



        result="Suspicious" if file.filename.endswith(
            (".exe",".bat",".dll")
        ) else "Safe"



        conn=db()


        conn.execute(

        """

        INSERT INTO malware

        VALUES(NULL,?,?,?,?)

        """,

        (

        file.filename,

        hash_value,

        result,

        datetime.now()

        )

        )


        conn.commit()

        conn.close()



        add_log(

        current_user.username,

        "Malware Scan Completed"

        )



        return "File Scanned"



    return render_template("upload.html")



# =========================
# PROFILE
# =========================


@app.route("/profile")

@login_required

def profile():

    return render_template(

    "profile.html"

    )



# =========================
# CHANGE PASSWORD
# =========================


@app.route("/change-password",
methods=["POST"])

@login_required

def change_password():


    new=request.form["password"]


    password=generate_password_hash(new)


    conn=db()


    conn.execute(

    """

    UPDATE users

    SET password=?

    WHERE id=?

    """,

    (

    password,

    current_user.id

    )

    )


    conn.commit()

    conn.close()



    return "Password Updated"



# =========================
# ACTIVITY LOGS
# =========================


@app.route("/logs")

@login_required

def logs():


    conn=db()


    data=conn.execute(

    "SELECT * FROM logs ORDER BY id DESC"

    ).fetchall()


    conn.close()


    return render_template(

    "logs.html",

    logs=data

    )



# =========================
# EMAIL ALERT
# =========================


@app.route("/alert")

@login_required

def alert():


    msg=Message(

    "CyberShield Alert",

    sender=app.config["MAIL_USERNAME"],

    recipients=[current_user.email]

    )


    msg.body="""

CyberShield detected suspicious activity.

Check your security dashboard.

"""


    mail.send(msg)


    return "Email Alert Sent"



# =========================
# START SERVER
# =========================


if __name__=="__main__":

    if not os.path.exists("uploads"):

        os.mkdir("uploads")


    app.run(

    host="0.0.0.0",

    port=5000,

    debug=True

    )

# ================================
# LIVE SIEM DASHBOARD
# ================================

@app.route("/siem")
@login_required
def siem_dashboard():

    conn = get_db_connection()
    cursor = conn.cursor()

    # Total Events
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_events = cursor.fetchone()[0]

    # Critical Events
    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='Critical'")
    critical = cursor.fetchone()[0]

    # High Events
    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='High'")
    high = cursor.fetchone()[0]

    # Medium Events
    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='Medium'")
    medium = cursor.fetchone()[0]

    # Low Events
    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='Low'")
    low = cursor.fetchone()[0]

    # Latest Events
    cursor.execute("""
    SELECT *
    FROM logs
    ORDER BY id DESC
    LIMIT 20
    """)

    events = cursor.fetchall()

    conn.close()

    return render_template(
        "siem_dashboard.html",
        total_events=total_events,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        events=events
    )
    
@app.route("/api/siem_stats")
@login_required
def siem_stats():

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='Critical'")
    critical = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='High'")
    high = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='Medium'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='Low'")
    low = cursor.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }
    
    
def add_log(event, severity, source):
    
    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO logs(
        event,
        severity,
        source,
        timestamp
    )
    VALUES(?,?,?,?)
    """,(
        event,
        severity,
        source,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()
    
add_log(
    "User Login",
    "Low",
    session["user"]
)

add_log(
    "User Logout",
    "Low",
    session["user"]
)

add_log(
    f"Incident Reported : {incident_name}",
    severity,
    session["user"]
)
add_log(
    f"Uploaded File : {filename}",
    "Medium",
    session["user"]
)

add_log(
    f"Malware Scan : {filename}",
    status,
    session["user"]
)