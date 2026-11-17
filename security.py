from datetime import datetime, timedelta, timezone
from functools import wraps
from uuid import uuid4

import bcrypt
import jwt
from flask import current_app, g, jsonify, request

from .models import User, UserSession, utcnow
from . import db


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _encode_token(user_id: int, token_type: str, expires_delta: timedelta, jti=None):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
        "jti": jti or str(uuid4()),
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET_KEY"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    ), payload


def create_token_pair(user: User):
    access, _ = _encode_token(
        user.id, "access",
        timedelta(minutes=current_app.config["ACCESS_TOKEN_MINUTES"])
    )
    refresh_jti = str(uuid4())
    refresh, claims = _encode_token(
        user.id, "refresh",
        timedelta(days=current_app.config["REFRESH_TOKEN_DAYS"]),
        jti=refresh_jti,
    )
    session = UserSession(
        user_id=user.id,
        refresh_jti=refresh_jti,
        expires_at=claims["exp"],
    )
    db.session.add(session)
    db.session.commit()
    return access, refresh


def decode_token(token: str):
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET_KEY"],
        algorithms=[current_app.config["JWT_ALGORITHM"]],
        options={"require": ["exp", "iat", "sub", "jti", "type"]},
    )


def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return jsonify({"error": "A Bearer access token is required."}), 401
        try:
            claims = decode_token(token)
            if claims.get("type") != "access":
                return jsonify({"error": "Use an access token for this endpoint."}), 401
            user = db.session.get(User, int(claims["sub"]))
            if not user:
                return jsonify({"error": "User no longer exists."}), 401
            g.current_user = user
        except (jwt.InvalidTokenError, ValueError, KeyError):
            return jsonify({"error": "Invalid or expired access token."}), 401
        return fn(*args, **kwargs)
    return wrapper
