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
from werkzeug.security import generate_password_hash, check_password_hash

"""V-APP-02 (Broken JWT) Fixed:
Use a strong server-side secret and only one permitted algorithm.
"""
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"

# ============================================================
# REMEDIATION BLOCK: Secure password storage and verification
#
# Passwords are never stored in plaintext. Werkzeug's PBKDF2-SHA256
# password hashing uses a unique salt and a deliberately expensive
# key-derivation function to make offline password cracking harder.
# Verification is performed against the stored password hash rather
# than comparing plaintext passwords.
# ============================================================

def hash_password(password: str) -> str:
    return generate_password_hash(
        password,
        method="pbkdf2:sha256",
        salt_length=16,
    )

def verify_password(password: str, stored_hash: str) -> bool:
    return check_password_hash(stored_hash, password)


def issue_token(user_id: int, role: str) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

"""Removed:
algorithms=["none"]
options={"verify_signature": False}
"""
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
