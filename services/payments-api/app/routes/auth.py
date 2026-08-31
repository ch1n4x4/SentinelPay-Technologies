"""Authentication routes: registration, login, OTP, and token refresh."""
import os
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import phonenumbers
from phonenumbers import NumberParseException
from flask import Blueprint, request, jsonify
from flask_limiter.util import get_remote_address

from app.extensions import limiter
from app.db import get_connection
from app.auth import hash_password, authenticate_user, issue_token

auth_bp = Blueprint("auth", __name__)


# ===========================================================================
# REMEDIATION START: V-APP-08 Canonical account identifiers for rate limiting
# ===========================================================================
PHONE_DEFAULT_REGION = os.environ.get("PHONE_DEFAULT_REGION", "NG")
RATE_LIMIT_KEY_SECRET = os.environ.get("RATE_LIMIT_KEY_SECRET", "default-dev-secret-replace-me")


def normalize_email(value: str) -> str:
    """Return one canonical representation for account-level email limits."""
    return value.strip().casefold()


def get_email_limit_key():
    data = request.get_json(silent=True) or {}
    email = data.get("email")

    if not email:
        return f"ip:{get_remote_address()}"

    return f"account:{normalize_email(email)}"


def normalize_phone(value: str) -> str:
    """
    Parse and canonicalize a phone number to E.164.

    Examples of equivalent inputs such as:
        +234 800 000 0000
        +234-800-000-0000
        0800 000 0000   (when PHONE_DEFAULT_REGION=NG)

    become one canonical value.
    """
    if not isinstance(value, str):
        raise ValueError("phone must be a string")

    raw = value.strip()

    if not raw:
        raise ValueError("phone is required")

    try:
        parsed = phonenumbers.parse(
            raw,
            PHONE_DEFAULT_REGION if not raw.startswith("+") else None,
        )
    except NumberParseException as exc:
        raise ValueError("invalid phone number") from exc

    if not phonenumbers.is_possible_number(parsed):
        raise ValueError("invalid phone number")

    if not phonenumbers.is_valid_number(parsed):
        raise ValueError("invalid phone number")

    return phonenumbers.format_number(
        parsed,
        phonenumbers.PhoneNumberFormat.E164,
    )


def _rate_limit_phone_key(phone_e164: str) -> str:
    """
    Deterministically derive a non-reversible rate-limit identifier.

    Phone numbers are PII and should not be written directly into the
    rate-limit backend key.
    """
    digest = hmac.new(
        RATE_LIMIT_KEY_SECRET.encode("utf-8"),
        phone_e164.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return digest


def lookup_account_id_by_phone(phone_e164: str):
    """
    Look up the canonical account using the canonical E.164 value.

    The users.phone column must contain the same canonical E.164 form.
    """
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id
            FROM users
            WHERE phone = %s
            """,
            (phone_e164,),
        )
        row = cur.fetchone()
        return row["id"] if row else None
    finally:
        cur.close()
        conn.close()


def get_otp_account_limit_key():
    """
    Account-level OTP rate-limit key.

    A valid phone number always maps to exactly one canonical E.164
    representation before the account lookup, preventing formatting-based
    limiter bypasses.
    """
    data = request.get_json(silent=True) or {}
    raw_phone = data.get("phone", "")

    try:
        phone_e164 = normalize_phone(raw_phone)
    except ValueError:
        # Invalid requests still receive an IP-based bucket and will be
        # rejected by the endpoint itself.
        return f"ip:{get_remote_address()}"

    account_id = lookup_account_id_by_phone(phone_e164)

    if account_id is None:
        # Do not expose the raw phone number in Redis or another limiter store.
        return f"unknown-phone:{_rate_limit_phone_key(phone_e164)}"

    return f"account:{account_id}"
# ===========================================================================
# REMEDIATION END: V-APP-08 Canonical account identifiers for rate limiting
# ===========================================================================


# REMEDIATION START: V-APP-02 Secure Refresh Token Hashing
def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
# REMEDIATION END


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=get_email_limit_key)
def register():
    """Register a new merchant account."""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name", "")
    
    role = "merchant"

    if not email or not password:
        return jsonify({"error": "email and password required"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, full_name, role) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (email, hash_password(password), full_name, role)
        )
        user_id = cur.fetchone()["id"]
        conn.commit()
        return jsonify({
            "id": user_id,
            "email": email,
            "role": role,
        }), 201
    finally:
        cur.close()
        conn.close()


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=get_email_limit_key)
def login():
    """Authenticate a user and issue a JWT alongside a secure refresh token."""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, password_hash, role, is_active "
            "FROM users WHERE email = %s",
            (email,),
        )

        user = cur.fetchone()

        if not user:
            return jsonify({"error": "invalid credentials"}), 401

        auth_result = authenticate_user(
            password,
            user["password_hash"],
        )
        
        if not auth_result:
            return jsonify({"error": "invalid credentials"}), 401
            
        if isinstance(auth_result, str):
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s", 
                (auth_result, user["id"]),
            )
            conn.commit()

        if not user["is_active"]:
            return jsonify({"error": "account suspended"}), 403

        access_token = issue_token(user["id"], user["role"])
        refresh_token = secrets.token_urlsafe(64)
        
        token_hash = hash_refresh_token(refresh_token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        cur.execute(
            """
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
            """,
            (user["id"], token_hash, expires_at),
        )
        conn.commit()

        return jsonify({
            "token": access_token,
            "refresh_token": refresh_token,
            "user_id": user["id"],
            "role": user["role"],
        })

    finally:
        cur.close()
        conn.close()


@auth_bp.route("/refresh", methods=["POST"])
@limiter.limit("10/minute")
def refresh():
    """Exchange a valid refresh token for a new access token and rotate the refresh credential."""
    data = request.get_json() or {}
    token = data.get("refresh_token")
    
    if not token:
        return jsonify({"error": "refresh_token required"}), 400
        
    conn = get_connection()
    cur = conn.cursor()
    try:
        token_hash = hash_refresh_token(token)
        
        cur.execute(
            """
            SELECT user_id, expires_at
            FROM refresh_tokens
            WHERE token_hash = %s
              AND revoked_at IS NULL
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        
        if not row or row["expires_at"] < datetime.now(timezone.utc):
            return jsonify({"error": "invalid or expired refresh token"}), 401
            
        user_id = row["user_id"]
        
        cur.execute(
            "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = %s",
            (token_hash,)
        )

        cur.execute("SELECT role, is_active FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        
        if not user or not user["is_active"]:
            return jsonify({"error": "account suspended"}), 403
            
        new_access_token = issue_token(user_id, user["role"])
        new_refresh_token = secrets.token_urlsafe(64)
        new_new_token_hash = hash_refresh_token(new_refresh_token)
        new_expires = datetime.now(timezone.utc) + timedelta(days=7)
        
        cur.execute(
            """
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (%s, %s, %s)
            """,
            (user_id, new_new_token_hash, new_expires)
        )
        conn.commit()
        
        return jsonify({
            "token": new_access_token,
            "refresh_token": new_refresh_token,
            "user_id": user_id,
            "role": user["role"]
        })
    finally:
        cur.close()
        conn.close()


@auth_bp.route("/otp", methods=["POST"])
# REMEDIATION START: V-APP-08 Dual-dimension Rate Limiting + Canonicalization
# Maintain the exact decorators for IP + canonical account scoping.
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=get_otp_account_limit_key)
def request_otp():
    """Request an OTP code for step-up authentication."""
    data = request.get_json(silent=True) or {}
    raw_phone = data.get("phone")

    try:
        # Canonicalize the phone before any further operation to ensure consistency.
        phone = normalize_phone(raw_phone)
    except ValueError:
        return jsonify({"error": "valid phone number required"}), 400

    # Generate/send the OTP using the canonical number.
    # Replaced insecure 'random' module with secure 'secrets' module.
    otp = f"{secrets.randbelow(900_000) + 100_000:06d}"

    return jsonify({
        "status": "sent",
        "phone": phone,
    })
# REMEDIATION END