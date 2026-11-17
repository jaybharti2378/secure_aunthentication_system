from datetime import datetime, timezone
import re

import jwt
from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import or_

from . import db
from .models import User, UserSession, utcnow
from .security import (
    create_token_pair, decode_token, hash_password, token_required, verify_password
)

auth_bp = Blueprint("auth", __name__)


def json_body():
    return request.get_json(silent=True) or {}


def valid_email(value):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value or ""))


@auth_bp.post("/register")
def register():
    data = json_body()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if len(username) < 3 or len(username) > 40:
        return jsonify({"error": "Username must be between 3 and 40 characters."}), 400
    if not valid_email(email):
        return jsonify({"error": "Enter a valid email address."}), 400
    if not isinstance(password, str) or len(password) < 8:
        return jsonify({"error": "Password must contain at least 8 characters."}), 400

    existing = User.query.filter(or_(User.username == username, User.email == email)).first()
    if existing:
        return jsonify({"error": "Username or email is already registered."}), 409

    user = User(username=username, email=email, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    access, refresh = create_token_pair(user)

    return jsonify({
        "message": "Registration successful.",
        "user": {"id": user.id, "username": user.username, "email": user.email},
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
    }), 201


@auth_bp.post("/login")
def login():
    data = json_body()
    identity = str(data.get("identity", "")).strip()
    password = data.get("password", "")

    user = User.query.filter(
        or_(User.username == identity, User.email == identity.lower())
    ).first()
    if not user or not isinstance(password, str) or not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid credentials."}), 401

    access, refresh = create_token_pair(user)
    return jsonify({
        "message": "Login successful.",
        "user": {"id": user.id, "username": user.username, "email": user.email},
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
    }), 200


@auth_bp.post("/refresh")
def refresh():
    data = json_body()
    token = data.get("refresh_token", "")
    if not token:
        return jsonify({"error": "refresh_token is required."}), 400

    try:
        claims = decode_token(token)
        if claims.get("type") != "refresh":
            return jsonify({"error": "A refresh token is required."}), 401
        session = UserSession.query.filter_by(refresh_jti=claims["jti"]).first()
        if not session or session.revoked_at is not None:
            return jsonify({"error": "Refresh session is invalid or revoked."}), 401
        if session.expires_at <= utcnow():
            return jsonify({"error": "Refresh session has expired."}), 401

        # Rotate refresh token: revoke the old session and issue a new pair.
        session.revoked_at = utcnow()
        user = db.session.get(User, int(claims["sub"]))
        if not user:
            db.session.commit()
            return jsonify({"error": "User no longer exists."}), 401
        db.session.commit()
        access, new_refresh = create_token_pair(user)
        return jsonify({
            "message": "Token refreshed.",
            "access_token": access,
            "refresh_token": new_refresh,
            "token_type": "Bearer",
        }), 200
    except (jwt.InvalidTokenError, ValueError, KeyError):
        return jsonify({"error": "Invalid or expired refresh token."}), 401


@auth_bp.post("/logout")
def logout():
    data = json_body()
    token = data.get("refresh_token", "")
    if not token:
        return jsonify({"error": "refresh_token is required."}), 400
    try:
        claims = decode_token(token)
        if claims.get("type") != "refresh":
            return jsonify({"error": "A refresh token is required."}), 401
        session = UserSession.query.filter_by(refresh_jti=claims["jti"]).first()
        if session and session.revoked_at is None:
            session.revoked_at = utcnow()
            db.session.commit()
        return jsonify({"message": "Logged out. Refresh session revoked."}), 200
    except (jwt.InvalidTokenError, ValueError, KeyError):
        return jsonify({"error": "Invalid or expired refresh token."}), 401


@auth_bp.get("/me")
@token_required
def me():
    user = g.current_user
    return jsonify({
        "user": {"id": user.id, "username": user.username, "email": user.email}
    }), 200
