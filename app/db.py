import sqlite3
from pathlib import Path
from flask import current_app, g


def get_db():
    if "db" not in g:
        db_path = Path(current_app.instance_path) / "secure_notes.db"

        Path(current_app.instance_path).mkdir(
            parents=True,
            exist_ok=True
        )

        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row

    return g.db


def close_db(e=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    db = get_db()

    schema_path = Path(current_app.root_path).parent / "schema.sql"

    with open(schema_path, "r", encoding="utf-8") as f:
        db.executescript(f.read())

    db.commit()


def init_app(app):
    app.teardown_appcontext(close_db)

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        print("Database initialized.")
