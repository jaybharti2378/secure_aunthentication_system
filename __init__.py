import os
from datetime import timedelta
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "dev-only-change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg2://postgres:postgres@localhost:5432/secure_auth_db",
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", "dev-jwt-secret-change-me"),
        JWT_ALGORITHM="HS256",
        ACCESS_TOKEN_MINUTES=int(os.getenv("ACCESS_TOKEN_MINUTES", "15")),
        REFRESH_TOKEN_DAYS=int(os.getenv("REFRESH_TOKEN_DAYS", "7")),
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)

    from .routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")

    @app.get("/")
    def home():
        return jsonify({
            "message": "Secure Authentication API",
            "endpoints": [
                "POST /api/auth/register",
                "POST /api/auth/login",
                "POST /api/auth/refresh",
                "POST /api/auth/logout",
                "GET /api/auth/me",
            ],
        })

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    with app.app_context():
        db.create_all()

    return app
