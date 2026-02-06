from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import datetime
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)

app = Flask(__name__)

# ================= JWT CONFIG =================
app.config["JWT_SECRET_KEY"] = "smart-stock-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=1)

# Use JWT in COOKIES (browser friendly)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False   # True only for HTTPS
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

jwt = JWTManager(app)

# ================= DATABASE =================
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# ================= HOME =================
@app.route("/")
def home():
    return render_template("auth.html")

# ================= SIGNUP =================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, "user")
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists ❌"

        conn.close()
        return redirect(url_for("login"))

    return render_template("signup.html")

# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM users WHERE username=? AND password=?",
            (username, password)
        )
        user = cur.fetchone()
        conn.close()

        if user:
            # ✅ JWT identity MUST be a STRING
            access_token = create_access_token(identity=str(user["id"]))

            response = redirect(url_for("user_dashboard"))
            response.set_cookie("access_token_cookie", access_token)
            return response

        return "Invalid username or password ❌"

    return render_template("login.html")

# ================= USER DASHBOARD =================
@app.route("/user-dashboard")
@jwt_required()
def user_dashboard():
    user_id = get_jwt_identity()
    return f"✅ Welcome USER {user_id}"

# ================= ADMIN DASHBOARD =================
@app.route("/admin-dashboard")
@jwt_required()
def admin_dashboard():
    user_id = get_jwt_identity()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    conn.close()

    if not user or user["role"] != "admin":
        return "Access denied ❌"

    return f"👑 Welcome ADMIN {user_id}"

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    response = redirect(url_for("login"))
    response.delete_cookie("access_token_cookie")
    return response

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)
