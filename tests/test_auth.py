PASSWORD = "Str0ngPassw0rd!"


def test_register_then_login_and_open_profile(make_user):
    client = make_user("alice")
    assert client.get("/auth/profile").status_code == 200


def test_password_is_stored_as_argon2_hash(make_user, db_query):
    make_user("alice", login=False)
    stored = db_query("SELECT password_hash FROM users WHERE username = ?", ("alice",))[0][0]
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_weak_password_is_rejected(app, db_query):
    resp = app.test_client().post("/auth/register", data={"username": "weak", "password": "short"})
    assert resp.status_code == 400
    assert db_query("SELECT id FROM users WHERE username = ?", ("weak",)) == []


def test_duplicate_username_is_rejected(app, make_user):
    make_user("alice", login=False)
    resp = app.test_client().post("/auth/register", data={"username": "alice", "password": PASSWORD})
    assert resp.status_code == 409


def test_wrong_password_gives_generic_error_and_no_session(app, make_user):
    make_user("alice", login=False)
    client = app.test_client()
    resp = client.post("/auth/login", data={"username": "alice", "password": "wrong-password"})
    assert resp.status_code == 401
    assert b"Invalid username or password." in resp.data
    assert client.get("/notes/").status_code == 302  # still not logged in


def test_unknown_user_gets_the_same_error(app):
    resp = app.test_client().post("/auth/login", data={"username": "ghost", "password": "whatever-123"})
    assert resp.status_code == 401
    assert b"Invalid username or password." in resp.data


def test_account_is_locked_after_five_failures(app, make_user):
    make_user("lockme", login=False)
    client = app.test_client()
    for _ in range(5):
        resp = client.post("/auth/login", data={"username": "lockme", "password": "wrong-password"})
        assert resp.status_code == 401
    resp = client.post("/auth/login", data={"username": "lockme", "password": PASSWORD})
    assert resp.status_code == 423  # locked, even with the correct password


def test_logins_are_written_to_the_audit_log(app, make_user, db_query):
    make_user("alice")
    app.test_client().post("/auth/login", data={"username": "alice", "password": "wrong-password"})
    actions = [r[0] for r in db_query("SELECT action FROM audit_log")]
    assert "login_success" in actions
    assert "login_failed" in actions


def test_logout_ends_the_session(make_user):
    client = make_user("alice")
    assert client.get("/notes/").status_code == 200
    client.post("/auth/logout")
    assert client.get("/notes/").status_code == 302


def test_csrf_token_is_required(app):
    app.config["WTF_CSRF_ENABLED"] = True
    resp = app.test_client().post("/auth/login", data={"username": "alice", "password": PASSWORD})
    assert resp.status_code == 400
