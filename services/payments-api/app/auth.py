"""Authentication helpers."""

import os
import hashlib
import secrets

from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import request, jsonify

import jwt

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerifyMismatchError,
)


# ============================================================================
# JWT CONFIGURATION
# ============================================================================
#
# REMEDIATION V-APP-02:
# main used the weaker symmetric JWT arrangement. The test branch uses an
# asymmetric RSA key pair:
#
#   JWT_PRIVATE_KEY -> used only to issue/sign access tokens
#   JWT_PUBLIC_KEY  -> used by verifiers such as payments-api/kyc-api
#
# The values are mandatory environment variables. There is deliberately no
# default secret, preventing the application from silently falling back to a
# known development credential.
JWT_PRIVATE_KEY = os.environ["JWT_PRIVATE_KEY"]
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]

JWT_ALGORITHM = "RS256"


# ============================================================================
# PASSWORD HASHING
# ============================================================================
#
# REMEDIATION V-APP-06:
# New passwords are stored using Argon2id through argon2-cffi rather than the
# legacy weak password hashing scheme.
password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a new password using Argon2id."""
    return password_hasher.hash(password)


def verify_password(
    password: str,
    stored_hash: str,
) -> bool:
    """Verify an existing Argon2id password hash."""
    try:
        return password_hasher.verify(
            stored_hash,
            password,
        )
    except (
        VerifyMismatchError,
        InvalidHashError,
    ):
        return False


# ============================================================================
# LEGACY PASSWORD MIGRATION
# ============================================================================
#
# REMEDIATION V-APP-06:
# Existing installations can contain legacy PBKDF2 or MD5 hashes. Successful
# verification of one of those hashes produces a new Argon2id hash.
#
# The caller is responsible for persisting the returned replacement hash.
# This permits gradual migration instead of invalidating every existing user.
def authenticate_user(
    password: str,
    stored_hash: str,
):
    """
    Verify a password.

    Returns:
        False -> authentication failed.
        True  -> current Argon2id hash is valid.
        str   -> legacy hash was valid; returned value is new Argon2id hash.
    """

    # ------------------------------------------------------------------------
    # Current Argon2id verification.
    # ------------------------------------------------------------------------
    try:
        if password_hasher.verify(
            stored_hash,
            password,
        ):
            # FUNCTIONALITY:
            # Upgrade an Argon2id record if its cost parameters need rehashing.
            if password_hasher.check_needs_rehash(
                stored_hash
            ):
                return password_hasher.hash(
                    password
                )

            return True

    except (
        VerifyMismatchError,
        InvalidHashError,
    ):
        pass

    # ------------------------------------------------------------------------
    # Legacy PBKDF2 migration.
    # ------------------------------------------------------------------------
    #
    # A successful legacy authentication immediately produces an Argon2id
    # replacement hash.
    if stored_hash.startswith("pbkdf2:"):
        from werkzeug.security import check_password_hash

        if check_password_hash(
            stored_hash,
            password,
        ):
            return password_hasher.hash(
                password
            )

    # ------------------------------------------------------------------------
    # Legacy MD5 migration.
    # ------------------------------------------------------------------------
    #
    # SECURITY:
    # MD5 is accepted only as a compatibility mechanism for existing records.
    # New passwords are never written as MD5.
    #
    # Remove this block after the legacy database population is fully migrated.
    if (
        len(stored_hash) == 32
        and all(
            character in "0123456789abcdef"
            for character in stored_hash.lower()
        )
    ):
        md5_hash = hashlib.md5(
            password.encode("utf-8")
        ).hexdigest()

        if secrets.compare_digest(
            md5_hash,
            stored_hash.lower(),
        ):
            return password_hasher.hash(
                password
            )

    return False


# ============================================================================
# ACCESS TOKEN ISSUANCE
# ============================================================================
#
# REMEDIATION V-APP-02:
# Access tokens are short-lived. A stolen token therefore has a bounded
# lifetime rather than remaining valid indefinitely.
def issue_token(
    user_id: int,
    role: str,
) -> str:
    """Create a short-lived RS256 JWT."""
    now = datetime.now(
        timezone.utc
    )

    payload = {
        "user_id": user_id,
        "role": role,
        "iat": now,
        "exp": (
            now
            + timedelta(minutes=15)
        ),
        "typ": "access",
    }

    token = jwt.encode(
        payload,
        JWT_PRIVATE_KEY,
        algorithm=JWT_ALGORITHM,
    )

    # PyJWT 2.x normally returns str. Keep compatibility with environments
    # where an implementation may return bytes.
    return (
        token.decode("utf-8")
        if isinstance(token, bytes)
        else token
    )


# ============================================================================
# ACCESS TOKEN VERIFICATION
# ============================================================================
#
# REMEDIATION V-APP-02:
# Explicitly reject any algorithm other than RS256 before cryptographic
# verification, then verify the signature with the public RSA key.
def decode_token(
    token: str,
) -> dict:
    header = jwt.get_unverified_header(
        token
    )

    if header.get("alg") != JWT_ALGORITHM:
        raise jwt.InvalidAlgorithmError(
            "unexpected JWT algorithm"
        )

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


# ============================================================================
# AUTHENTICATION DECORATOR
# ============================================================================
#
# FUNCTIONALITY:
# Extract a bearer token and expose the authenticated identity to the route
# through request.current_user_id and request.current_user_role.
#
# REMEDIATION V-APP-09:
# Do not return PyJWT exception details to unauthenticated callers. Validation
# failures return the same generic response regardless of the internal reason.
def require_auth(f):
    """Require a valid cryptographically verified JWT."""
    @wraps(f)
    def wrapper(
        *args,
        **kwargs,
    ):
        auth_header = request.headers.get(
            "Authorization",
            "",
        )

        if not auth_header.startswith(
            "Bearer "
        ):
            return jsonify({
                "error": "unauthorized"
            }), 401

        token = auth_header[
            len("Bearer "):
        ].strip()

        if not token:
            return jsonify({
                "error": "unauthorized"
            }), 401

        try:
            payload = decode_token(
                token
            )

        except jwt.PyJWTError:
            return jsonify({
                "error": "unauthorized"
            }), 401

        request.current_user_id = (
            payload["user_id"]
        )

        request.current_user_role = (
            payload["role"]
        )

        return f(
            *args,
            **kwargs,
        )

    return wrapper