from flask import Flask, render_template, request, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "cybershield_secret_key"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template("dashboard.html")


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


@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect("/")


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


@app.route("/reports")
def reports():

    conn = sqlite3.connect("cybershield.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM incidents")

    incidents = cursor.fetchall()

    conn.close()

    return render_template(
        "reports.html",
        incidents=incidents
    )


if __name__ == "__main__":
    app.run(debug=True)