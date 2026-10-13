import sqlite3
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint,
    request,
    render_template,
    redirect,
    url_for,
    session,
    abort,
)

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from app.db import get_db
from app.auth_utils import login_required
from app.audit import log_action
from app.extensions import limiter


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
ph = PasswordHasher()

MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15


@auth_bp.route("/register", methods=("GET", "POST"))
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return "Username and password are required.", 400

        if len(username) > 80 or len(password) > 128:
            return "Input is too long.", 400

        if len(password) < 12 or not (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
        ):
            return "Password: 12+ characters with upper, lower and a digit.", 400

        password_hash = ph.hash(password)
        db = get_db()

        try:
            cur = db.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (username, password_hash),
            )
            db.commit()
            new_user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            db.rollback()
            return "Username already exists.", 409

        log_action("register_success", new_user_id)
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=("GET", "POST"))
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            """
            SELECT id, username, password_hash, role, failed_attempts, locked_until
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if user is None:
            log_action("login_failed_unknown_user", None)
            return "Invalid username or password.", 401

        if user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > datetime.now(timezone.utc):
            log_action("login_blocked_locked", user["id"])
            return "Account temporarily locked. Try again later.", 423

        try:
            ph.verify(user["password_hash"], password)
        except (VerifyMismatchError, VerificationError):
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)).isoformat()
                attempts = 0
                log_action("account_locked", user["id"])
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            db.commit()
            log_action("login_failed", user["id"])
            return "Invalid username or password.", 401

        if ph.check_needs_rehash(user["password_hash"]):
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (ph.hash(password), user["id"]),
            )
            db.commit()

        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        db.commit()

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session.permanent = True
        log_action("login_success", user["id"])

        if user["role"] == "ADMIN":
            return redirect(url_for("auth.admin"))

        return redirect(url_for("auth.profile"))

    return render_template("login.html")


@auth_bp.route("/profile")
@login_required
def profile():
    if session.get("role") == "ADMIN":
        return redirect(url_for("auth.admin"))

    return render_template("dashboard.html")


@auth_bp.route("/admin")
@login_required
def admin():
    if session.get("role") != "ADMIN":
        log_action("admin_access_denied", session["user_id"])
        abort(403)

    db = get_db()
    users = db.execute(
        """
        SELECT id, username, role
        FROM users
        ORDER BY username
        """
    ).fetchall()

    return render_template("admin.html", users=users)


@auth_bp.route("/logout", methods=("POST",))
@login_required
def logout():
    log_action("logout", session.get("user_id"))
    session.clear()
    return redirect(url_for("auth.login"))
