from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import sqlite3
from functools import wraps
from datetime import datetime, date
import random

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"

socketio = SocketIO(app, cors_allowed_origins="*")

DB = "high_flyer.db"


# ============================================================
# DATABASE
# ============================================================

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

    CREATE TABLE IF NOT EXISTS point_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_id INTEGER NOT NULL,
        admin_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        transaction_type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(player_id) REFERENCES players(id),
        FOREIGN KEY(admin_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS game_rounds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_id INTEGER NOT NULL,
        stake REAL NOT NULL,
        multiplier REAL DEFAULT 1.00,
        collected_points REAL DEFAULT 0,
        status TEXT DEFAULT 'playing',
        created_at TEXT NOT NULL,
        collected_at TEXT,
        FOREIGN KEY(player_id) REFERENCES players(id)
    );
    """)

    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        ("owner",)
    ).fetchone()

    if not existing:
        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, role, created_at)
            VALUES (?, ?, 'super_admin', ?)
            """,
            (
                "owner",
                generate_password_hash("ChangeMe123!"),
                datetime.utcnow().isoformat()
            )
        )

    conn.commit()
    conn.close()


# ============================================================
# AUTHENTICATION
# ============================================================

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


# ============================================================
# HOME / LOGIN
# ============================================================

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
            """
            SELECT *
            FROM users
            WHERE username = ?
            AND active = 1
            """,
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(url_for("dashboard"))

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = db()

    # ---------------- SUPER ADMIN ----------------

    if session["role"] == "super_admin":

        admins = conn.execute(
            """
            SELECT
                u.id,
                u.username,
                u.active,
                a.balance
            FROM users u
            JOIN admin_accounts a
                ON a.user_id = u.id
            WHERE u.role = 'admin'
            ORDER BY u.id DESC
            """
        ).fetchall()

        conn.close()

        return render_template(
            "super_admin.html",
            admins=admins
        )

    # ---------------- ADMIN ----------------

    admin = conn.execute(
        """
        SELECT
            u.id,
            u.username,
            a.id AS admin_account_id,
            a.balance
        FROM users u
        JOIN admin_accounts a
            ON a.user_id = u.id
        WHERE u.id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    players = conn.execute(
        """
        SELECT *
        FROM players
        WHERE admin_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        admin=admin,
        players=players
    )


# ============================================================
# CREATE ADMIN
# ============================================================

@app.route("/admin/create", methods=["POST"])
@login_required
@super_admin_required
def create_admin():

    username = request.form["username"].strip()
    password = request.form["password"]

    if not username or not password:

        flash(
            "Username and password are required.",
            "error"
        )

        return redirect(url_for("dashboard"))

    conn = db()

    try:

        cur = conn.execute(
            """
            INSERT INTO users
            (username, password_hash, role, created_at)
            VALUES (?, ?, 'admin', ?)
            """,
            (
                username,
                generate_password_hash(password),
                datetime.utcnow().isoformat()
            )
        )

        conn.execute(
            """
            INSERT INTO admin_accounts
            (user_id, balance)
            VALUES (?, 0)
            """,
            (cur.lastrowid,)
        )

        conn.commit()

        flash(
            "Admin account created.",
            "success"
        )

    except sqlite3.IntegrityError:

        flash(
            "That username already exists.",
            "error"
        )

    finally:

        conn.close()

    return redirect(url_for("dashboard"))


# ============================================================
# SUPER ADMIN → ADMIN FLOAT
# ============================================================

@app.route("/admin/float", methods=["POST"])
@login_required
@super_admin_required
def add_float():

    admin_id = int(request.form["admin_id"])
    amount = float(request.form["amount"])

    if amount <= 0:

        flash(
            "Enter an amount greater than zero.",
            "error"
        )

        return redirect(url_for("dashboard"))

    conn = db()

    conn.execute(
        """
        UPDATE admin_accounts
        SET balance = balance + ?
        WHERE user_id = ?
        """,
        (amount, admin_id)
    )

    conn.execute(
        """
        INSERT INTO float_transactions
        (admin_id, amount, created_by, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            admin_id,
            amount,
            session["user_id"],
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    socketio.emit(
        "balance_updated",
        {"admin_id": admin_id}
    )

    flash(
        "Float added successfully.",
        "success"
    )

    return redirect(url_for("dashboard"))


# ============================================================
# ADMIN → CREATE PLAYER
# ============================================================

@app.route("/player/create", methods=["POST"])
@login_required
def create_player():

    if session["role"] != "admin":

        flash(
            "Only admins can create players.",
            "error"
        )

        return redirect(url_for("dashboard"))

    username = request.form["username"].strip()

    if not username:

        flash(
            "Enter a player username.",
            "error"
        )

        return redirect(url_for("dashboard"))

    conn = db()

    conn.execute(
        """
        INSERT INTO players
        (admin_id, username, balance, created_at)
        VALUES (?, ?, 0, ?)
        """,
        (
            session["user_id"],
            username,
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    flash(
        "Player created.",
        "success"
    )

    return redirect(url_for("dashboard"))


# ============================================================
# ADMIN → ADD PLAYER POINTS
# ============================================================

@app.route("/player/add-points", methods=["POST"])
@login_required
def add_player_points():

    if session["role"] != "admin":

        flash(
            "Only admins can add player points.",
            "error"
        )

        return redirect(url_for("dashboard"))

    try:

        player_id = int(request.form["player_id"])
        amount = float(request.form["amount"])

    except (ValueError, TypeError):

        flash(
            "Invalid player or amount.",
            "error"
        )

        return redirect(url_for("dashboard"))

    # Minimum 10 points
    if amount < 10:

        flash(
            "Minimum points allocation is 10.",
            "error"
        )

        return redirect(url_for("dashboard"))

    conn = db()

    player = conn.execute(
        """
        SELECT *
        FROM players
        WHERE id = ?
        AND admin_id = ?
        AND active = 1
        """,
        (
            player_id,
            session["user_id"]
        )
    ).fetchone()

    admin = conn.execute(
        """
        SELECT balance
        FROM admin_accounts
        WHERE user_id = ?
        AND active = 1
        """,
        (session["user_id"],)
    ).fetchone()

    if not player:

        conn.close()

        flash(
            "Player not found.",
            "error"
        )

        return redirect(url_for("dashboard"))

    if not admin or admin["balance"] < amount:

        conn.close()

        flash(
            "Not enough admin float.",
            "error"
        )

        return redirect(url_for("dashboard"))

    # Deduct from admin's virtual float
    conn.execute(
        """
        UPDATE admin_accounts
        SET balance = balance - ?
        WHERE user_id = ?
        """,
        (
            amount,
            session["user_id"]
        )
    )

    # Add points to player
    conn.execute(
        """
        UPDATE players
        SET balance = balance + ?
        WHERE id = ?
        """,
        (
            amount,
            player_id
        )
    )

    # Record transaction
    conn.execute(
        """
        INSERT INTO point_transactions
        (
            player_id,
            admin_id,
            amount,
            transaction_type,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            player_id,
            session["user_id"],
            amount,
            "admin_allocation",
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    socketio.emit(
        "player_balance_updated",
        {
            "player_id": player_id
        }
    )

    flash(
        f"{amount:g} points added to player.",
        "success"
    )

    return redirect(url_for("dashboard"))


@app.route("/player/withdraw-points", methods=["POST"])
def withdraw_player_points():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    player_id = request.form.get("player_id")
    amount_text = request.form.get("amount", "").strip()

    try:
        amount = int(amount_text)
    except ValueError:
        flash("Enter a valid points amount.", "error")
        return redirect(url_for("admin_dashboard"))

    if amount <= 0:
        flash("Points must be greater than zero.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    cursor = conn.cursor()

    # Get the logged-in admin
    cursor.execute(
        "SELECT * FROM admin_accounts WHERE id = ?",
        (session["admin_id"],)
    )
    admin = cursor.fetchone()

    # Get the player
    cursor.execute(
        "SELECT * FROM players WHERE id = ?",
        (player_id,)
    )
    player = cursor.fetchone()

    if not admin or not player:
        conn.close()
        flash("Admin or player not found.", "error")
        return redirect(url_for("admin_dashboard"))

    if player["balance"] < amount:
        conn.close()
        flash("Player does not have enough points.", "error")
        return redirect(url_for("admin_dashboard"))

    # Remove points from player
    cursor.execute(
        """
        UPDATE players
        SET balance = balance - ?
        WHERE id = ?
        """,
        (amount, player_id)
    )

    # Return points to admin float
    cursor.execute(
        """
        UPDATE admin_accounts
        SET balance = balance + ?
        WHERE id = ?
        """,
        (amount, admin["id"])
    )

# Record transaction
@app.route("/player/withdraw-points", methods=["POST"])
@login_required


    if session["role"] != "admin":
        flash("Only admins can withdraw player points.", "error")
        return redirect(url_for("dashboard"))

    try:
        player_id = int(request.form["player_id"])
        amount = float(request.form["amount"])
    except (ValueError, TypeError):
        flash("Invalid player or amount.", "error")
        return redirect(url_for("dashboard"))

    if amount <= 0:
        flash("Points must be greater than zero.", "error")
        return redirect(url_for("dashboard"))

    # Remove points from player
    conn.execute(
        """
        UPDATE players
        SET balance = balance - ?
        WHERE id = ?
        """,
        (
            amount,
            player_id
        )
    )

    # Return points to this admin's float
    conn.execute(
        """
        UPDATE admin_accounts
        SET balance = balance + ?
        WHERE user_id = ?
        """,
        (
            amount,
            session["user_id"]
        )
    )

    # Record transaction
    conn.execute(
        """
        INSERT INTO point_transactions
        (
            player_id,
            admin_id,
            amount,
            transaction_type,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            player_id,
            session["user_id"],
            amount,
            "withdraw_from_player",
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    flash(
        f"{amount:g} points returned to your float.",
        "success"
    )

    return redirect(url_for("dashboard"))
# ============================================================
# GAME
# ============================================================

@app.route("/game")
@login_required
def game():

    conn = db()

    if session["role"] == "admin":

        players = conn.execute(
            """
            SELECT
                p.id,
                p.username,
                p.balance
            FROM players p
            WHERE p.admin_id = ?
            AND p.active = 1
            ORDER BY p.id
            """,
            (session["user_id"],)
        ).fetchall()

        conn.close()

        return render_template(
            "game.html",
            players=players,
            role="admin"
        )

    # A player account can be supported by session later.
    conn.close()

    return render_template(
        "game.html",
        players=[],
        role=session["role"]
    )


# ============================================================
# START POINTS-ONLY ROUND
# ============================================================

@app.route("/player/play", methods=["POST"])
@login_required
def player_play():

    if session["role"] != "admin":

        return jsonify({
            "success": False,
            "message": "Admin game-control access required."
        }), 403

    try:

        player_id = int(request.form["player_id"])
        stake = float(request.form["stake"])

    except (ValueError, TypeError):

        return jsonify({
            "success": False,
            "message": "Invalid player or points amount."
        }), 400

    if stake <= 0:

        return jsonify({
            "success": False,
            "message": "Points must be greater than zero."
        }), 400

    conn = db()

    player = conn.execute(
        """
        SELECT *
        FROM players
        WHERE id = ?
        AND admin_id = ?
        AND active = 1
        """,
        (
            player_id,
            session["user_id"]
        )
    ).fetchone()

    if not player:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Player not found."
        }), 404

    if player["balance"] < stake:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Player does not have enough points."
        }), 400

    # Prevent multiple active rounds
    active_round = conn.execute(
        """
        SELECT id
        FROM game_rounds
        WHERE player_id = ?
        AND status = 'playing'
        """,
        (player_id,)
    ).fetchone()

    if active_round:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Player already has an active round."
        }), 400

    # Deduct stake
    conn.execute(
        """
        UPDATE players
        SET balance = balance - ?
        WHERE id = ?
        """,
        (
            stake,
            player_id
        )
    )

    # Create round
    cur = conn.execute(
        """
        INSERT INTO game_rounds
        (
            player_id,
            stake,
            multiplier,
            status,
            created_at
        )
        VALUES (?, ?, 1.00, 'playing', ?)
        """,
        (
            player_id,
            stake,
            datetime.utcnow().isoformat()
        )
    )

    round_id = cur.lastrowid

    conn.execute(
        """
        INSERT INTO point_transactions
        (
            player_id,
            admin_id,
            amount,
            transaction_type,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            player_id,
            session["user_id"],
            -stake,
            "game_stake",
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "round_id": round_id,
        "stake": stake
    })


@app.route("/player/collect", methods=["POST"])
@login_required
def player_collect():

    if session["role"] != "admin":

        return jsonify({
            "success": False,
            "message": "Admin game-control access required."
        }), 403

    try:

        round_id = int(request.form["round_id"])
        multiplier = float(request.form["multiplier"])

    except (ValueError, TypeError):

        return jsonify({
            "success": False,
            "message": "Invalid round."
        }), 400

    if multiplier < 1:

        return jsonify({
            "success": False,
            "message": "Invalid multiplier."
        }), 400

    conn = db()

    round_row = conn.execute(
        """
        SELECT
            r.*,
            p.admin_id
        FROM game_rounds r
        JOIN players p
            ON p.id = r.player_id
        WHERE r.id = ?
        AND p.admin_id = ?
        AND r.status = 'playing'
        """,
        (
            round_id,
            session["user_id"]
        )
    ).fetchone()

    if not round_row:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Active round not found."
        }), 404

    collected = round_row["stake"] * multiplier

    conn.execute(
        """
        UPDATE players
        SET balance = balance + ?
        WHERE id = ?
        """,
        (
            collected,
            round_row["player_id"]
        )
    )

    conn.execute(
        """
        UPDATE game_rounds
        SET
            multiplier = ?,
            status = 'collected',
            collected_points = ?,
            collected_at = ?
        WHERE id = ?
        """,
        (
            multiplier,
            collected,
            datetime.utcnow().isoformat(),
            round_id
        )
    )

    conn.execute(
        """
        INSERT INTO point_transactions
        (
            player_id,
            admin_id,
            amount,
            transaction_type,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            round_row["player_id"],
            session["user_id"],
            collected,
            "game_collect",
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "points": collected,
        "multiplier": multiplier
    })




@app.route("/player/balance/<int:player_id>")
@login_required
def player_balance(player_id):

    if session["role"] != "admin":

        return jsonify({
            "success": False,
            "message": "Access denied."
        }), 403

    conn = db()

    player = conn.execute(
        """
        SELECT id, username, balance
        FROM players
        WHERE id = ?
        AND admin_id = ?
        """,
        (
            player_id,
            session["user_id"]
        )
    ).fetchone()

    conn.close()

    if not player:

        return jsonify({
            "success": False,
            "message": "Player not found."
        }), 404

    return jsonify({
        "success": True,
        "player_id": player["id"],
        "username": player["username"],
        "balance": player["balance"]
    })




@app.route("/player/history/<int:player_id>")
@login_required
def player_history(player_id):

    if session["role"] != "admin":

        return jsonify({
            "success": False,
            "message": "Access denied."
        }), 403

    conn = db()

    rows = conn.execute(
        """
        SELECT
            amount,
            transaction_type,
            created_at
        FROM point_transactions
        WHERE player_id = ?
        AND admin_id = ?
        ORDER BY id DESC
        LIMIT 100
        """,
        (
            player_id,
            session["user_id"]
        )
    ).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "transactions": [
            dict(row)
            for row in rows
        ]
    })



@socketio.on("join_game")
def join_game(data):

    emit(
        "player_joined",
        {
            "username": data.get(
                "username",
                "Player"
            )
        },
        broadcast=True
    )


@socketio.on("game_message")
def game_message(data):

    emit(
        "game_message",
        data,
        broadcast=True
    )



def get_db():
    conn = sqlite3.connect("high_flyer.db")
    conn.row_factory = sqlite3.Row
    return conn



if __name__ == "__main__":

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True
    )
