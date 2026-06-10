from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/register", methods=["GET","POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("cybershield.db")
        cursor = conn.cursor()

        cursor.execute(
        "INSERT INTO users(username,email,password) VALUES(?,?,?)",
        (username,email,password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("cybershield.db")
        cursor = conn.cursor()

        cursor.execute(
        "SELECT * FROM users WHERE email=? AND password=?",
        (email,password)
        )

        user = cursor.fetchone()

        conn.close()

        if user:
            return redirect("/dashboard")

    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)