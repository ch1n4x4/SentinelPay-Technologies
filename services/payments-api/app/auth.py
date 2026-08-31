"""Authentication helpers."""
import os
# REMEDIATION START: V-APP-06 Legacy MD5 Migration
# Imported hashlib and secrets to securely compare legacy MD5 hashes[cite: 40].
import hashlib
import secrets
# REMEDIATION END
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

JWT_PRIVATE_KEY = os.environ["JWT_PRIVATE_KEY"]
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ALGORITHM = "RS256"

password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# REMEDIATION START: V-APP-06 Legacy Hash Migration (Helper)
# Recognizes existing legacy PBKDF2 hashes and, after successful verification, 
# flags them for replacement with an Argon2id hash without breaking existing logins.
def authenticate_user(password: str, stored_hash: str):
    """
    Verify the password.

    Returns:
      False  -> authentication failed
      True   -> current hash is valid and up to date
      str    -> valid legacy hash that has been rehashed
    """
    try:
        if password_hasher.verify(stored_hash, password):
            if password_hasher.check_needs_rehash(stored_hash):
                return password_hasher.hash(password)
            return True
    except (VerifyMismatchError, InvalidHashError):
        pass

    # Support for legacy PBKDF2 hashes during migration window
    if stored_hash.startswith("pbkdf2:"):
        from werkzeug.security import check_password_hash
        if check_password_hash(stored_hash, password):
            return password_hasher.hash(password)

    # REMEDIATION START: V-APP-06 Legacy MD5 Migration
    # Explicitly support the known legacy MD5 format during the migration window 
    # to migrate actual seeded legacy users[cite: 40]. This compatibility check 
    # should be removed after all legacy hashes have migrated[cite: 40].
    if len(stored_hash) == 32 and all(
        c in "0123456789abcdef"
        for c in stored_hash.lower()
    ):
        md5_hash = hashlib.md5(
            password.encode("utf-8")
        ).hexdigest()

        if secrets.compare_digest(md5_hash, stored_hash.lower()):
            return password_hasher.hash(password)
    # REMEDIATION END

    return False
# REMEDIATION END


def issue_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "user_id": user_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "typ": "access",
    }

    token = jwt.encode(
        payload,
        JWT_PRIVATE_KEY,
        algorithm=JWT_ALGORITHM,
    )
    return token.decode("utf-8") if isinstance(token, bytes) else token


def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        JWT_PUBLIC_KEY,
        algorithms=[JWT_ALGORITHM],
        options={
            "verify_signature": True,
            "verify_exp": True,
            "require": [
                "user_id",
                "role",
                "iat",
                "exp",
            ],
        },
    )


def require_auth(f):
    """Decorator that extracts the current user from the Authorization header."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401

        token = auth_header[len("Bearer "):].strip()

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