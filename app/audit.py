from flask import current_app, request

from app.db import get_db


def log_action(action, user_id=None):
    """Record a security-relevant event. A logging failure never breaks the request."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, action, ip_address) VALUES (?, ?, ?)",
            (user_id, action, request.remote_addr),
        )
        db.commit()
    except Exception:
        current_app.logger.exception("audit log write failed")
