import os
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask
from flask_wtf.csrf import CSRFProtect

from .db import init_app
from .extensions import limiter
from .routes.auth import auth_bp
from .routes.notes import notes_bp


def create_app():
    load_dotenv()

    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Set to True once the app is served over HTTPS (OpenSSL certificate).
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

    CSRFProtect(app)
    limiter.init_app(app)

    init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(notes_bp)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/")
    def home():
        return "Secure Notes - Flask application is running!"

    return app
