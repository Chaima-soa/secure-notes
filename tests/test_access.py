def test_notes_require_login(app):
    resp = app.test_client().get("/notes/")
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_normal_user_cannot_open_admin_page(make_user, db_query):
    client = make_user("alice")
    assert client.get("/auth/admin").status_code == 403
    actions = [r[0] for r in db_query("SELECT action FROM audit_log")]
    assert "admin_access_denied" in actions


def test_admin_can_open_admin_page(make_user):
    admin = make_user("boss", role="ADMIN")
    assert admin.get("/auth/admin").status_code == 200


def test_user_cannot_read_another_users_note(make_user, db_query):
    alice = make_user("alice")
    bob = make_user("bob")
    alice.post("/notes/create", data={"title": "Alice private", "content": "alice secret"})
    note_id = db_query("SELECT id FROM notes WHERE title = ?", ("Alice private",))[0][0]

    assert alice.get("/notes/" + str(note_id)).status_code == 200
    assert bob.get("/notes/" + str(note_id)).status_code == 403

    actions = [r[0] for r in db_query("SELECT action FROM audit_log")]
    assert "note_access_denied" in actions


def test_unknown_note_gives_404(make_user):
    assert make_user("alice").get("/notes/99999").status_code == 404


def test_security_headers_are_present(app):
    resp = app.test_client().get("/auth/login")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "same-origin"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Cache-Control"] == "no-store"
