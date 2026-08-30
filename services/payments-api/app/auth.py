"""Authentication helpers.

NOTE TO MAINTAINERS: this module was last touched 14 months ago. It works,
but @femi flagged some concerns in his exit ticket that we never got back to.
See PR #284 (closed without merge).
"""
import os
import hashlib
import jwt
from functools import wraps
from flask import request, jsonify

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """Hash a password for storage.

    V-APP-06: Uses MD5 with no salt. Trivially reversible for common passwords
    via rainbow tables, and MD5 is cryptographically broken regardless.
    """
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash


def issue_token(user_id: int, role: str) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        options={
            "verify_signature": True,
            "require": ["user_id", "role"],
        },
    )


def require_auth(f):
    """Decorator that extracts the current user from the Authorization header."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing or malformed Authorization header"}), 401

        token = auth_header.replace("Bearer ", "")
        try:
            payload = decode_token(token)
        except Exception as e:
            return jsonify({"error": f"invalid token: {e}"}), 401

        request.current_user_id = payload.get("user_id")
        request.current_user_role = payload.get("role")
        return f(*args, **kwargs)
    return wrapper
