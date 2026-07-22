from flask import Flask, render_template, request, redirect, session, send_file
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.pdfgen import canvas
import os
from network.scanner import scan_network

app = Flask(__name__)
app.secret_key = "cybershield_secret_key"


@app.route("/")
def home():
    return render_template("index.html")
@app.route("/malware_scan", methods=["GET", "POST"])
@app.route("/scan_result/<int:id>")
@app.route("/malware_history")
@app.route("/download_scan_report/<int:id>")


# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("cybershield.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]
    except:
        total_incidents = 0

    conn.close()

    return render_template(
        "dashboard.html",
        username=session["user"],
        total_incidents=total_incidents
    )


# ================= REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]

        password = generate_password_hash(
            request.form["password"]
        )

        conn = sqlite3.connect("cybershield.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users
            (username,email,password)
            VALUES(?,?,?)
            """,
            (username, email, password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("cybershield.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[3], password):

            session["user"] = user[1]

            return redirect("/dashboard")

        return "Invalid Email or Password"

    return render_template("login.html")


# ================= LOGOUT =================

@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect("/")


# ================= REPORT INCIDENT =================

@app.route("/report", methods=["GET", "POST"])
def report():

    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":

        incident_name = request.form["incident_name"]
        severity = request.form["severity"]
        description = request.form["description"]

        conn = sqlite3.connect("cybershield.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO incidents
            (incident_name,severity,description)
            VALUES(?,?,?)
            """,
            (incident_name, severity, description)
        )

        conn.commit()
        conn.close()

        return redirect("/dashboard")

    return render_template("report_incident.html")


# ================= REPORTS =================

@app.route("/reports")
def reports():

    if "user" not in session:
        return redirect("/login")

    search = request.args.get("search", "")
    severity = request.args.get("severity", "")

    conn = sqlite3.connect("cybershield.db")
    cursor = conn.cursor()

    query = "SELECT * FROM incidents WHERE 1=1"
    params = []

    if search:
        query += " AND incident_name LIKE ?"
        params.append(f"%{search}%")

    if severity:
        query += " AND severity=?"
        params.append(severity)

    try:
        cursor.execute(query, params)
        incidents = cursor.fetchall()
    except:
        incidents = []
        

    conn.close()

    return render_template(
        "reports.html",
        incidents=incidents
    )


# ================= AI ASSISTANT =================

@app.route("/assistant", methods=["GET", "POST"])
def assistant():

    if "user" not in session:
        return redirect("/login")

    answer = ""

    if request.method == "POST":

        question = request.form["question"].lower()

        if "password" in question:
            answer = "Use strong passwords and enable MFA."

        elif "phishing" in question:
            answer = "Verify sender identity before clicking links."

        elif "malware" in question:
            answer = "Use antivirus and keep software updated."

        elif "ransomware" in question:
            answer = "Maintain backups and avoid unknown downloads."

        elif "wifi" in question:
            answer = "Use WPA2/WPA3 encryption and strong passwords."

        else:
            answer = "Follow cybersecurity best practices."

    return render_template(
        "assistant.html",
        answer=answer
    )


# ================= RISK ASSESSMENT =================

@app.route("/risk")
def risk():

    if "user" not in session:
        return redirect("/login")

    return render_template("risk.html")
@app.route("/threat_intelligence")
def threat_intelligence():

    if "user" not in session:
        return redirect("/login")

    return render_template("threat_intelligence.html")
@app.route("/network_scan", methods=["GET","POST"])
def network_scan():

    if "user" not in session:
        return redirect("/login")

    devices=[]

    if request.method=="POST":

        target=request.form["target"]

        devices=scan_network(target)

    return render_template(
        "network_scan.html",
        devices=devices
    )

    
# ================= ADMIN DASHBOARD =================

@app.route("/admin")
def admin():

    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("cybershield.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
    except:
        total_users = 0

    try:
        cursor.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = cursor.fetchone()[0]
    except:
        total_incidents = 0

    try:
        cursor.execute(
            "SELECT COUNT(*) FROM incidents WHERE severity='Critical'"
        )
        critical_incidents = cursor.fetchone()[0]
    except:
        critical_incidents = 0

    conn.close()

    return render_template(
        "admin.html",
        username=session["user"],
        total_users=total_users,
        total_incidents=total_incidents,
        critical_incidents=critical_incidents
    )# ================= USERS =================

@app.route("/users")
def users():

    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("cybershield.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT id,username,email FROM users"
        )

        users = cursor.fetchall()

    except:

        users = []

    conn.close()

    return render_template(
        "users.html",
        users=users
    )# ================= DELETE INCIDENT =================

@app.route("/delete_incident/<int:id>")
def delete_incident(id):

    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("cybershield.db")
    cursor = conn.cursor()

    try:

        cursor.execute(
            "DELETE FROM incidents WHERE id=?",
            (id,)
        )

        conn.commit()

    except:

        pass

    conn.close()

    return redirect("/reports")
# ================= DELETE USER =================

@app.route("/delete_user/<int:id>")
def delete_user(id):

    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("cybershield.db")
    cursor = conn.cursor()

    try:

        cursor.execute(
            "DELETE FROM users WHERE id=?",
            (id,)
        )

        conn.commit()

    except:

        pass

    conn.close()

    return redirect("/users")
from flask_mail import Mail, Message

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your_email@gmail.com"
app.config["MAIL_PASSWORD"] = "your_app_password"

mail = Mail(app)
@app.route("/hash_check", methods=["GET","POST"])
def hash_check():

    if "user" not in session:
        return redirect("/login")

    hash_value = ""

    if request.method == "POST":
        hash_value = request.form["hash"]

    return render_template(
        "hash_check.html",
        hash_value=hash_value
    )
@app.route("/ip_lookup", methods=["GET","POST"])
def ip_lookup():

    if "user" not in session:
        return redirect("/login")

    ip = ""
    country = ""
    isp = ""
    risk = ""

    if request.method == "POST":

        ip = request.form["ip"]

        # Dummy Data
        country = "United States"
        isp = "Google LLC"
        risk = "Low"

    return render_template(
        "ip_lookup.html",
        ip=ip,
        country=country,
        isp=isp,
        risk=risk
    )
    
@app.route("/url_scan", methods=["GET","POST"])
def url_scan():

    if "user" not in session:
        return redirect("/login")

    return render_template("url_scan.html")
if __name__ == "__main__":
    app.run(debug=True)