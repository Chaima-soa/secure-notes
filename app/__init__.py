from flask import Flask
from .db import init_app


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = "dev-secret-key"

    init_app(app)

    @app.route("/")
    def home():
        return "Secure Notes - Flask application is running!"

    return app
