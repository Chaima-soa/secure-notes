from flask import Blueprint, request, render_template, redirect, url_for, session, abort

from app.db import get_db
from app.auth_utils import login_required
from app.crypto import encrypt_note, decrypt_note
from app.integrity import compute_hmac, verify_hmac
from app.audit import log_action


notes_bp = Blueprint("notes", __name__, url_prefix="/notes")


@notes_bp.route("/")
@login_required
def index():
    db = get_db()

    notes = db.execute(
        """
        SELECT id, title, encrypted_content, hmac, created_at, updated_at
        FROM notes
        WHERE user_id = ?
        ORDER BY updated_at DESC
        """,
        (session["user_id"],),
    ).fetchall()

    decrypted_notes = []

    for note in notes:
        if verify_hmac(session["user_id"], note["title"],
                       note["encrypted_content"], note["hmac"]):
            content = decrypt_note(note["encrypted_content"])
        else:
            content = "[INTEGRITY ERROR: this note was modified]"

        decrypted_notes.append(
            {
                "id": note["id"],
                "title": note["title"],
                "content": content,
                "created_at": note["created_at"],
                "updated_at": note["updated_at"],
            }
        )

    return render_template("notes.html", notes=decrypted_notes)


@notes_bp.route("/create", methods=("GET", "POST"))
@login_required
def create():
    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"]

        if not title or not content:
            return "Title and content are required.", 400

        if len(title) > 100:
            return "Title is too long.", 400

        if len(content) > 10000:
            return "Content is too long.", 400

        encrypted_content = encrypt_note(content)
        mac = compute_hmac(session["user_id"], title, encrypted_content)

        db = get_db()

        db.execute(
            """
            INSERT INTO notes (user_id, title, encrypted_content, hmac)
            VALUES (?, ?, ?, ?)
            """,
            (session["user_id"], title, encrypted_content, mac),
        )

        db.commit()
        log_action("note_created", session["user_id"])

        return redirect(url_for("notes.index"))

    return render_template("create_note.html")


@notes_bp.route("/<int:note_id>")
@login_required
def view(note_id):
    db = get_db()

    note = db.execute(
        """
        SELECT id, user_id, title, encrypted_content, hmac, created_at, updated_at
        FROM notes
        WHERE id = ?
        """,
        (note_id,),
    ).fetchone()

    if note is None:
        abort(404)

    if note["user_id"] != session["user_id"]:
        log_action("note_access_denied", session["user_id"])
        abort(403)

    if not verify_hmac(note["user_id"], note["title"],
                       note["encrypted_content"], note["hmac"]):
        abort(500, "Integrity check failed: this note was modified.")

    return render_template(
        "view_note.html",
        note={
            "id": note["id"],
            "title": note["title"],
            "content": decrypt_note(note["encrypted_content"]),
            "created_at": note["created_at"],
            "updated_at": note["updated_at"],
        },
    )


@notes_bp.route("/<int:note_id>/delete", methods=("POST",))
@login_required
def delete(note_id):
    db = get_db()

    note = db.execute(
        """
        SELECT id, user_id
        FROM notes
        WHERE id = ?
        """,
        (note_id,),
    ).fetchone()

    if note is None:
        abort(404)

    if note["user_id"] != session["user_id"]:
        abort(403)

    db.execute(
        "DELETE FROM notes WHERE id = ?",
        (note_id,),
    )

    db.commit()
    log_action("note_deleted", session["user_id"])

    return redirect(url_for("notes.index"))
