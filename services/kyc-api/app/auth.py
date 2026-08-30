"""Authentication helpers for the KYC API."""
import os
import jwt
from functools import wraps
from flask import request, jsonify

"""V-APP-02 (Broken JWT) Fixed:
Use a strong server-side secret and only one permitted algorithm.
"""
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"


def decode_token(token: str) -> dict:
    """Decode and cryptographically verify a JWT.

    Only HS256 is accepted and signature verification is mandatory.
    """
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
    """Require a valid, signed JWT in the Authorization header."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401

        token = auth[len("Bearer "):].strip()

        if not token:
            return jsonify({"error": "unauthorized"}), 401

        try:
            payload = decode_token(token)
        except jwt.PyJWTError:
            return jsonify({"error": "unauthorized"}), 401

        request.current_user_id = payload["user_id"]
        request.current_user_role = payload["role"]

        return f(*args, **kwargs)

    return wrapper