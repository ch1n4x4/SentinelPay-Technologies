"""Authentication routes: registration, login, OTP, and token refresh."""

import hashlib
import hmac
import os
import secrets
import psycopg2.errors
from datetime import datetime, timedelta, timezone

import phonenumbers
from phonenumbers import NumberParseException
from flask import Blueprint, jsonify, request
from flask_limiter.util import get_remote_address

from app.auth import authenticate_user, hash_password, issue_token
from app.db import get_connection
from app.extensions import limiter


auth_bp = Blueprint("auth", __name__)


# ============================================================================
# V-APP-08: Canonical account identifiers for rate limiting
# ============================================================================

# Default region used only for national-format numbers such as 0800...
# Configure explicitly in deployment; NG is the application's current default.
PHONE_DEFAULT_REGION = os.environ.get("PHONE_DEFAULT_REGION", "NG")

# Mandatory secret used to derive non-reversible rate-limit keys for
# unregistered phone numbers. Do NOT provide a hardcoded fallback.
RATE_LIMIT_KEY_SECRET = os.environ["RATE_LIMIT_KEY_SECRET"]


def normalize_email(value: str) -> str:
    """Return one canonical representation for account-level email limits."""
    if not isinstance(value, str):
        raise ValueError("email must be a string")

    normalized = value.strip().casefold()

    if not normalized:
        raise ValueError("email is required")

    return normalized


def get_email_limit_key():
    """
    Return the account-level login/register bucket.

    Known accounts are keyed by canonical email representation.
    Requests without an email fall back to the IP bucket.
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email")

    if not isinstance(email, str) or not email.strip():
        return f"ip:{get_remote_address()}"

    return f"account:{normalize_email(email)}"


def normalize_phone(value: str) -> str:
    """
    Parse and canonicalize a phone number to E.164.

    Examples:
        +234 800 000 0000
        +234-800-000-0000
        0800 000 0000

    become one canonical representation when PHONE_DEFAULT_REGION=NG:
        +2348000000000

    Invalid or ambiguous phone numbers are rejected rather than normalized
    into a potentially different identity.
    """
    if not isinstance(value, str):
        raise ValueError("phone must be a string")

    raw = value.strip()

    if not raw:
        raise ValueError("phone is required")

    try:
        # International numbers must include their country code.
        # National numbers are interpreted using the configured default region.
        region = None if raw.startswith("+") else PHONE_DEFAULT_REGION

        parsed = phonenumbers.parse(raw, region)
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
    Derive a deterministic, non-reversible identifier for an unknown phone.

    Phone numbers are PII, so the raw canonical number is never placed
    directly into the rate-limit backend.
    """
    digest = hmac.new(
        RATE_LIMIT_KEY_SECRET.encode("utf-8"),
        phone_e164.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"phone:{digest}"


def get_otp_account_limit_key():
    """
    Return a deterministic account-level OTP rate-limit key.

    The phone number is normalized to E.164 first, so equivalent
    representations of the same number share one rate-limit bucket.

    Examples:
        +234 800 000 0000
        +234-800-000-0000
        0800 000 0000

    all resolve to the same canonical identity when PHONE_DEFAULT_REGION=NG.
    """
    data = request.get_json(silent=True) or {}
    raw_phone = data.get("phone", "")

    try:
        phone_e164 = normalize_phone(raw_phone)
    except ValueError:
        # Invalid requests are separately rejected by the endpoint.
        # Keep them in the IP bucket so malformed input cannot generate
        # arbitrary account identities.
        return f"ip:{get_remote_address()}"

    digest = hmac.new(
        RATE_LIMIT_KEY_SECRET.encode("utf-8"),
        phone_e164.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"account-phone:{digest}"

# ============================================================================
# V-APP-02: Secure refresh-token hashing
# ============================================================================

def hash_refresh_token(token: str) -> str:
    """Hash a refresh token before storing or looking it up."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ============================================================================
# Registration
# ============================================================================

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=get_email_limit_key)
def register():
    """Register a new merchant account."""
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name", "")

    role = "merchant"

    if not isinstance(email, str) or not email.strip():
        return jsonify({"error": "email and password required"}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "email and password required"}), 400

    email = normalize_email(email)

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            INSERT INTO users (
                email,
                password_hash,
                full_name,
                role
            )
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                email,
                hash_password(password),
                full_name,
                role,
            ),
        )

        user_id = cur.fetchone()["id"]
        conn.commit()

        return jsonify(
            {
                "id": user_id,
                "email": email,
                "role": role,
            }
        ), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "A user with that email already exists"}), 409
    finally:
        cur.close()
        conn.close()


# ============================================================================
# Login
# ============================================================================

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=get_email_limit_key)
def login():
    """Authenticate a user and issue an access token and refresh token."""
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not email.strip():
        return jsonify({"error": "invalid credentials"}), 401

    if not isinstance(password, str):
        return jsonify({"error": "invalid credentials"}), 401

    email = normalize_email(email)

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT
                id,
                password_hash,
                role,
                is_active
            FROM users
            WHERE email = %s
            """,
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

        # Legacy password migration:
        # authenticate_user() may return a newly generated Argon2 hash.
        if isinstance(auth_result, str):
            cur.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE id = %s
                """,
                (
                    auth_result,
                    user["id"],
                ),
            )

        if not user["is_active"]:
            return jsonify({"error": "account suspended"}), 403

        access_token = issue_token(
            user["id"],
            user["role"],
        )

        refresh_token = secrets.token_urlsafe(64)
        token_hash = hash_refresh_token(refresh_token)

        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(days=7)
        )

        cur.execute(
            """
            INSERT INTO refresh_tokens (
                user_id,
                token_hash,
                expires_at
            )
            VALUES (%s, %s, %s)
            """,
            (
                user["id"],
                token_hash,
                expires_at,
            ),
        )

        conn.commit()

        return jsonify(
            {
                "token": access_token,
                "refresh_token": refresh_token,
                "user_id": user["id"],
                "role": user["role"],
            }
        )

    finally:
        cur.close()
        conn.close()


# ============================================================================
# Refresh token
# ============================================================================

@auth_bp.route("/refresh", methods=["POST"])
@limiter.limit("10/minute")
def refresh():
    """
    Exchange a valid refresh token for a new access token and rotate the
    refresh credential.
    """
    data = request.get_json(silent=True) or {}
    token = data.get("refresh_token")

    if not isinstance(token, str) or not token:
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

        if not row:
            return jsonify(
                {"error": "invalid or expired refresh token"}
            ), 401

        if row["expires_at"] < datetime.now(timezone.utc):
            return jsonify(
                {"error": "invalid or expired refresh token"}
            ), 401

        user_id = row["user_id"]

        cur.execute(
            """
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE token_hash = %s
            """,
            (token_hash,),
        )

        cur.execute(
            """
            SELECT role, is_active
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        )

        user = cur.fetchone()

        if not user or not user["is_active"]:
            conn.rollback()
            return jsonify({"error": "account suspended"}), 403

        new_access_token = issue_token(
            user_id,
            user["role"],
        )

        new_refresh_token = secrets.token_urlsafe(64)
        new_token_hash = hash_refresh_token(new_refresh_token)

        new_expires = (
            datetime.now(timezone.utc)
            + timedelta(days=7)
        )

        cur.execute(
            """
            INSERT INTO refresh_tokens (
                user_id,
                token_hash,
                expires_at
            )
            VALUES (%s, %s, %s)
            """,
            (
                user_id,
                new_token_hash,
                new_expires,
            ),
        )

        conn.commit()

        return jsonify(
            {
                "token": new_access_token,
                "refresh_token": new_refresh_token,
                "user_id": user_id,
                "role": user["role"],
            }
        )

    finally:
        cur.close()
        conn.close()


# ============================================================================
# OTP
# ============================================================================

@auth_bp.route("/otp", methods=["POST"])
@limiter.limit("5/minute")
@limiter.limit(
    "5/minute",
    key_func=get_otp_account_limit_key,
)
def request_otp():
    """
    Request an OTP code for step-up authentication.

    The phone number is canonicalized before use so formatting differences
    cannot create separate account/rate-limit identities.
    """
    data = request.get_json(silent=True) or {}
    raw_phone = data.get("phone")

    try:
        phone = normalize_phone(raw_phone)
    except ValueError:
        return jsonify(
            {"error": "valid phone number required"}
        ), 400

    # Cryptographically secure OTP generation.
    otp = f"{secrets.randbelow(900_000) + 100_000:06d}"

    # TODO:
    # Persist only a hash of the OTP, with:
    #   - short expiration
    #   - single-use semantics
    #   - verification-attempt limit
    #
    # Example:
    #
    # otp_hash = hashlib.sha256(otp.encode("utf-8")).hexdigest()
    # store_otp_hash(phone, otp_hash, expires_at=...)

    # Send the OTP through the application's SMS provider here.
    # The plaintext OTP must never be logged.

    return jsonify(
        {
            "status": "sent",
            "phone": phone,
        }
    )
