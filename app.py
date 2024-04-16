from cs50 import SQL
import pprint
from flask import Flask, render_template, request, session, redirect
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import login_required, check_password

# Configuring the application
app = Flask(__name__)

# database
db = SQL("sqlite:///database.db")

# Configuring the session
app.config["SESSION_PERMENENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/")
@login_required
def home():
    # Home screen
    return render_template("layout.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        error = None
        if not username:
            error = "Please enter an username"

        elif not password:
            error = "Please enter a password"

        else:
            rows = db.execute(
                "SELECT * FROM ent WHERE username = ?", username
            )

            if len(rows) != 1 or not check_password_hash(
                rows[0]["password_hash"], password
            ):
                error = "invalid username and/or password"

        if error is None:
            session["user_id"] = rows[0]["id"]
            return redirect("/")
        else:
            return render_template("login.html", error=error)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        confirmation = request.form.get("confirmation")
        error = None
        success = None
        if not username:
            error = "Please enter a username"
        elif not password:
            error = "Please enter a password"
        elif not check_password(password):
            error = "Password doesn't meet requirements"
        elif not confirmation:
            error = "Password confirmation is required"
        elif not email:
            error = "Please enter your college email"
        elif password != confirmation:
            error = "Password confirmation did not match"
        password_hash = generate_password_hash(password)
        if error is None:
            try:
                db.execute(
                    "INSERT INTO ent (username, password_HASH, email) VALUES (?, ?, ?)",
                    username,
                    password_hash,
                    email)
                return render_template("register.html", error=error, success="Registration Successful!")
            except:
                return render_template("register.html", error="Username and/or email has already been registered", success=success)
        else:
            return render_template("register.html", error=error, success=success)
    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == '__main__':
    app.run(debug=True)