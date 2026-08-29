"""Shared auth helpers (duplicated from payments-api — known tech debt)."""
import os
import jwt
from functools import wraps
from flask import request, jsonify

JWT_SECRET = os.environ.get("JWT_SECRET", "sentinelpay-dev-secret")


def decode_token(token: str) -> dict:
    # Same broken verifier as payments-api. Two services, one bug.
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"], options={"verify_signature": False})


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        try:
            payload = decode_token(auth.replace("Bearer ", ""))
        except Exception:
            return jsonify({"error": "unauthorized"}), 401
        request.current_user_id = payload.get("user_id")
        request.current_user_role = payload.get("role")
        return f(*args, **kwargs)
    return wrapper
