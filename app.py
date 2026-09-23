from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import sqlite3
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
socketio = SocketIO(app, cors_allowed_origins="*")

DB = "high_flyer.db"

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('super_admin','admin')),
        active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        balance REAL DEFAULT 0,
        active INTEGER DEFAULT 1,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS players (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        balance REAL DEFAULT 0,
        active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY(admin_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS float_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        created_by INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(admin_id) REFERENCES users(id),
        FOREIGN KEY(created_by) REFERENCES users(id)
    );
    """)

    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", ("owner",)
    ).fetchone()

    if not existing:
        conn.execute(
            """INSERT INTO users
               (username, password_hash, role, created_at)
               VALUES (?, ?, 'super_admin', ?)""",
            ("owner", generate_password_hash("ChangeMe123!"),
             datetime.utcnow().isoformat())
        )

    conn.commit()
    conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def super_admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "super_admin":
            flash("Super Admin access required.", "error")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn = db()

    if session["role"] == "super_admin":
        admins = conn.execute("""
            SELECT u.id, u.username, u.active, a.balance
            FROM users u
            JOIN admin_accounts a ON a.user_id = u.id
            WHERE u.role = 'admin'
            ORDER BY u.id DESC
        """).fetchall()
        conn.close()
        return render_template("super_admin.html", admins=admins)

    admin = conn.execute("""
        SELECT u.username, a.balance
        FROM users u
        JOIN admin_accounts a ON a.user_id = u.id
        WHERE u.id = ?
    """, (session["user_id"],)).fetchone()

    players = conn.execute("""
        SELECT * FROM players
        WHERE admin_id = ?
        ORDER BY id DESC
    """, (session["user_id"],)).fetchall()

    conn.close()
    return render_template("admin.html", admin=admin, players=players)

@app.route("/admin/create", methods=["POST"])
@login_required
@super_admin_required
def create_admin():
    username = request.form["username"].strip()
    password = request.form["password"]

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("dashboard"))

    conn = db()
    try:
        cur = conn.execute("""
            INSERT INTO users
            (username, password_hash, role, created_at)
            VALUES (?, ?, 'admin', ?)
        """, (username, generate_password_hash(password),
              datetime.utcnow().isoformat()))

        conn.execute(
            "INSERT INTO admin_accounts (user_id, balance) VALUES (?, 0)",
            (cur.lastrowid,)
        )
        conn.commit()
        flash("Admin account created.", "success")
    except sqlite3.IntegrityError:
        flash("That username already exists.", "error")
    finally:
        conn.close()

    return redirect(url_for("dashboard"))

@app.route("/admin/float", methods=["POST"])
@login_required
@super_admin_required
def add_float():
    admin_id = int(request.form["admin_id"])
    amount = float(request.form["amount"])

    if amount <= 0:
        flash("Enter an amount greater than zero.", "error")
        return redirect(url_for("dashboard"))

    conn = db()
    conn.execute(
        "UPDATE admin_accounts SET balance = balance + ? WHERE user_id = ?",
        (amount, admin_id)
    )
    conn.execute("""
        INSERT INTO float_transactions
        (admin_id, amount, created_by, created_at)
        VALUES (?, ?, ?, ?)
    """, (admin_id, amount, session["user_id"], datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    socketio.emit("balance_updated", {"admin_id": admin_id})
    flash("Float added successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/player/create", methods=["POST"])
@login_required
def create_player():
    username = request.form["username"].strip()

    if not username:
        flash("Enter a player username.", "error")
        return redirect(url_for("dashboard"))

    conn = db()
    conn.execute("""
        INSERT INTO players (admin_id, username, balance, created_at)
        VALUES (?, ?, 0, ?)
    """, (session["user_id"], username, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))

@app.route("/game")
@login_required
def game():
    conn = db()
    players = conn.execute("""
        SELECT p.id, p.username, p.balance
        FROM players p
        WHERE p.admin_id = ? AND p.active = 1
        ORDER BY p.id
    """, (session["user_id"],)).fetchall()
    conn.close()
    return render_template("game.html", players=players)

@socketio.on("join_game")
def join_game(data):
    emit("player_joined", {
        "username": data.get("username", "Player")
    }, broadcast=True)

if __name__ == "__main__":
    init_db()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
