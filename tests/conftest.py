import pytest

from app import create_app
from app.db import get_db, init_db

try:
    from app.extensions import limiter
except ImportError:  # limiter not installed in this project version
    limiter = None

PASSWORD = "Str0ngPassw0rd!"

# Columns added after the first schema.sql: make sure the test database has them.
EXTRA_COLUMNS = {
    "users": [
        ("failed_attempts", "INTEGER NOT NULL DEFAULT 0"),
        ("locked_until", "TEXT"),
        ("session_version", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "notes": [("hmac", "TEXT")],
    "audit_log": [("ip_address", "TEXT")],
}


@pytest.fixture(autouse=True)
def test_keys(monkeypatch):
    """Fixed keys, so the tests never depend on (or touch) your real .env."""
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("AES_KEY", "11" * 32)
    monkeypatch.setenv("HMAC_KEY", "22" * 32)


@pytest.fixture
def app(tmp_path):
    app = create_app()
    app.instance_path = str(tmp_path)               # temporary database
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False          # re-enabled in the CSRF test
    app.config["SESSION_COOKIE_SECURE"] = False     # test client speaks plain HTTP
    if limiter is not None:
        limiter.enabled = False
        limiter.reset()
    with app.app_context():
        init_db()
        db = get_db()
        for table, columns in EXTRA_COLUMNS.items():
            existing = {r[1] for r in db.execute("PRAGMA table_info(" + table + ")")}
            for name, ddl in columns:
                if name not in existing:
                    db.execute("ALTER TABLE " + table + " ADD COLUMN " + name + " " + ddl)
        db.commit()
    return app


@pytest.fixture
def db_query(app):
    def run(sql, params=()):
        with app.app_context():
            return [tuple(r) for r in get_db().execute(sql, params).fetchall()]
    return run


@pytest.fixture
def db_exec(app):
    def run(sql, params=()):
        with app.app_context():
            db = get_db()
            db.execute(sql, params)
            db.commit()
    return run


@pytest.fixture
def make_user(app, db_exec):
    """Create an account and return a test client (logged in by default)."""
    def make(username, role="USER", login=True):
        client = app.test_client()
        resp = client.post("/auth/register", data={"username": username, "password": PASSWORD})
        assert resp.status_code == 302, resp.data
        if role != "USER":
            db_exec("UPDATE users SET role = ? WHERE username = ?", (role, username))
        if login:
            resp = client.post("/auth/login", data={"username": username, "password": PASSWORD})
            assert resp.status_code == 302, resp.data
        return client
    return make
