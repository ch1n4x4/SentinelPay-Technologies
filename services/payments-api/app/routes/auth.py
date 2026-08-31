"""Authentication routes: registration, login, OTP, and token refresh."""

import hashlib
import hmac
import os
import secrets

from datetime import (
    datetime,
    timedelta,
    timezone,
)

import phonenumbers

from phonenumbers import (
    NumberParseException,
)

from flask import (
    Blueprint,
    jsonify,
    request,
)

from flask_limiter.util import (
    get_remote_address,
)

from app.auth import (
    authenticate_user,
    hash_password,
    issue_token,
)

from app.db import get_connection
from app.extensions import limiter


auth_bp = Blueprint(
    "auth",
    __name__,
)


# ============================================================================
# V-APP-08: CANONICAL ACCOUNT IDENTIFIERS
# ============================================================================
#
# FUNCTIONALITY:
# Authentication requests need deterministic account identities so equivalent
# representations cannot bypass account-level rate limits.
PHONE_DEFAULT_REGION = os.environ.get(
    "PHONE_DEFAULT_REGION",
    "NG",
)


# SECURITY:
# This secret is mandatory and has no hardcoded fallback. It is used for HMAC
# bucketing of unknown phone numbers.
RATE_LIMIT_KEY_SECRET = os.environ[
    "RATE_LIMIT_KEY_SECRET"
]


def normalize_email(
    value: str,
) -> str:
    """
    Canonicalize an email address for account lookup/rate limiting.
    """
    if not isinstance(
        value,
        str,
    ):
        raise ValueError(
            "email must be a string"
        )

    normalized = value.strip().casefold()

    if not normalized:
        raise ValueError(
            "email is required"
        )

    return normalized


def get_email_limit_key():
    """
    Return the account-scoped login/register bucket.

    The standard limiter still provides IP-based throttling. This second
    limiter makes repeated attacks against one email expensive even when
    requests originate from different IP addresses.
    """
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    email = data.get(
        "email"
    )

    if (
        not isinstance(
            email,
            str,
        )
        or not email.strip()
    ):
        return (
            f"ip:{get_remote_address()}"
        )

    return (
        f"account:"
        f"{normalize_email(email)}"
    )


def normalize_phone(
    value: str,
) -> str:
    """
    Canonicalize a phone number as E.164.

    This ensures different formatting of the same phone number maps to the
    same account/rate-limit identity.
    """
    if not isinstance(
        value,
        str,
    ):
        raise ValueError(
            "phone must be a string"
        )

    raw = value.strip()

    if not raw:
        raise ValueError(
            "phone is required"
        )

    try:
        region = (
            None
            if raw.startswith("+")
            else PHONE_DEFAULT_REGION
        )

        parsed = phonenumbers.parse(
            raw,
            region,
        )

    except NumberParseException as exc:
        raise ValueError(
            "invalid phone number"
        ) from exc

    if not phonenumbers.is_possible_number(
        parsed
    ):
        raise ValueError(
            "invalid phone number"
        )

    if not phonenumbers.is_valid_number(
        parsed
    ):
        raise ValueError(
            "invalid phone number"
        )

    return phonenumbers.format_number(
        parsed,
        phonenumbers.PhoneNumberFormat.E164,
    )


def _rate_limit_phone_key(
    phone_e164: str,
) -> str:
    """
    Generate a deterministic non-reversible bucket for unknown phone numbers.

    The raw phone number is PII and therefore is not stored directly in the
    rate-limit backend.
    """
    digest = hmac.new(
        RATE_LIMIT_KEY_SECRET.encode(
            "utf-8"
        ),
        phone_e164.encode(
            "utf-8"
        ),
        hashlib.sha256,
    ).hexdigest()

    return f"phone:{digest}"


def lookup_account_id_by_phone(
    phone_e164: str,
):
    """
    Find a known user's account identity from its canonical phone number.
    """
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id
            FROM users
            WHERE phone = %s
            LIMIT 1
            """,
            (phone_e164,),
        )

        row = cur.fetchone()

        if not row:
            return None

        return row["id"]

    finally:
        cur.close()
        conn.close()


def get_otp_account_limit_key():
    """
    Return the account-scoped OTP bucket.

    Known users are keyed by internal account ID. Unknown valid numbers use
    an HMAC-derived phone bucket. Invalid numbers fall back to the IP bucket,
    while the endpoint itself rejects the invalid number.
    """
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    raw_phone = data.get(
        "phone"
    )

    try:
        phone_e164 = normalize_phone(
            raw_phone
        )
    except ValueError:
        return (
            f"ip:{get_remote_address()}"
        )

    account_id = lookup_account_id_by_phone(
        phone_e164
    )

    if account_id is not None:
        return f"account:{account_id}"

    return _rate_limit_phone_key(
        phone_e164
    )


# ============================================================================
# V-APP-02: REFRESH-TOKEN STORAGE
# ============================================================================
#
# SECURITY:
# The refresh-token itself is a bearer credential. Only a SHA-256 digest is
# stored in PostgreSQL so compromise of the database does not immediately
# expose usable refresh credentials.
def hash_refresh_token(
    token: str,
) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# ============================================================================
# REGISTRATION
# ============================================================================

@auth_bp.route(
    "/register",
    methods=["POST"],
)
@limiter.limit(
    "5/minute"
)
@limiter.limit(
    "5/minute",
    key_func=get_email_limit_key,
)
def register():
    """
    Register a new merchant.

    REMEDIATION V-APP-07:
    Public clients cannot choose their own authorization role. Registration
    always creates the server-selected merchant role.
    """
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    email = data.get(
        "email"
    )

    password = data.get(
        "password"
    )

    full_name = data.get(
        "full_name",
        "",
    )

    # SECURITY:
    # Never accept role from client input.
    role = "merchant"

    if (
        not isinstance(
            email,
            str,
        )
        or not email.strip()
    ):
        return jsonify({
            "error": (
                "email and password required"
            )
        }), 400

    if (
        not isinstance(
            password,
            str,
        )
        or not password
    ):
        return jsonify({
            "error": (
                "email and password required"
            )
        }), 400

    email = normalize_email(
        email
    )

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
            VALUES (
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
            """,
            (
                email,
                hash_password(
                    password
                ),
                full_name,
                role,
            ),
        )

        user_id = cur.fetchone()[
            "id"
        ]

        conn.commit()

        return jsonify({
            "id": user_id,
            "email": email,
            "role": role,
        }), 201

    finally:
        cur.close()
        conn.close()


# ============================================================================
# LOGIN
# ============================================================================

@auth_bp.route(
    "/login",
    methods=["POST"],
)
@limiter.limit(
    "5/minute"
)
@limiter.limit(
    "5/minute",
    key_func=get_email_limit_key,
)
def login():
    """
    Authenticate a user and issue access and refresh tokens.

    REMEDIATION V-APP-06:
    Successful legacy-password authentication is followed by immediate
    persistence of the replacement Argon2id hash.
    """
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    email = data.get(
        "email"
    )

    password = data.get(
        "password"
    )

    if (
        not isinstance(
            email,
            str,
        )
        or not email.strip()
    ):
        return jsonify({
            "error": "invalid credentials"
        }), 401

    if not isinstance(
        password,
        str,
    ):
        return jsonify({
            "error": "invalid credentials"
        }), 401

    email = normalize_email(
        email
    )

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
            return jsonify({
                "error": "invalid credentials"
            }), 401

        auth_result = authenticate_user(
            password,
            user["password_hash"],
        )

        if not auth_result:
            return jsonify({
                "error": "invalid credentials"
            }), 401

        # --------------------------------------------------------------------
        # LEGACY PASSWORD MIGRATION
        # --------------------------------------------------------------------
        #
        # A string return value represents a newly generated Argon2id hash.
        if isinstance(
            auth_result,
            str,
        ):
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

        if not user[
            "is_active"
        ]:
            return jsonify({
                "error": "account suspended"
            }), 403

        access_token = issue_token(
            user["id"],
            user["role"],
        )

        # --------------------------------------------------------------------
        # REFRESH TOKEN
        # --------------------------------------------------------------------
        #
        # Generate a strong random bearer token. Persist only its digest.
        refresh_token = (
            secrets.token_urlsafe(64)
        )

        token_hash = hash_refresh_token(
            refresh_token
        )

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
            VALUES (
                %s,
                %s,
                %s
            )
            """,
            (
                user["id"],
                token_hash,
                expires_at,
            ),
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


# ============================================================================
# REFRESH TOKEN ROTATION
# ============================================================================

@auth_bp.route(
    "/refresh",
    methods=["POST"],
)
@limiter.limit(
    "10/minute"
)
def refresh():
    """
    Exchange a refresh token for a new token pair.

    SECURITY:
    A used refresh token is revoked before its replacement is persisted,
    preventing simple replay of the original refresh credential.
    """
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    token = data.get(
        "refresh_token"
    )

    if (
        not isinstance(
            token,
            str,
        )
        or not token
    ):
        return jsonify({
            "error": (
                "refresh_token required"
            )
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        token_hash = (
            hash_refresh_token(
                token
            )
        )

        cur.execute(
            """
            SELECT
                user_id,
                expires_at
            FROM refresh_tokens
            WHERE token_hash = %s
              AND revoked_at IS NULL
            """,
            (token_hash,),
        )

        row = cur.fetchone()

        if not row:
            return jsonify({
                "error": (
                    "invalid or expired "
                    "refresh token"
                )
            }), 401

        if row[
            "expires_at"
        ] < datetime.now(
            timezone.utc
        ):
            return jsonify({
                "error": (
                    "invalid or expired "
                    "refresh token"
                )
            }), 401

        user_id = row[
            "user_id"
        ]

        # Revoke the consumed credential.
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
            SELECT
                role,
                is_active
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        )

        user = cur.fetchone()

        if (
            not user
            or not user[
                "is_active"
            ]
        ):
            conn.rollback()

            return jsonify({
                "error": "account suspended"
            }), 403

        new_access_token = issue_token(
            user_id,
            user["role"],
        )

        new_refresh_token = (
            secrets.token_urlsafe(64)
        )

        new_token_hash = (
            hash_refresh_token(
                new_refresh_token
            )
        )

        new_expires = (
            datetime.now(
                timezone.utc
            )
            + timedelta(days=7)
        )

        cur.execute(
            """
            INSERT INTO refresh_tokens (
                user_id,
                token_hash,
                expires_at
            )
            VALUES (
                %s,
                %s,
                %s
            )
            """,
            (
                user_id,
                new_token_hash,
                new_expires,
            ),
        )

        conn.commit()

        return jsonify({
            "token": new_access_token,
            "refresh_token": new_refresh_token,
            "user_id": user_id,
            "role": user["role"],
        })

    finally:
        cur.close()
        conn.close()


# ============================================================================
# OTP
# ============================================================================

@auth_bp.route(
    "/otp",
    methods=["POST"],
)
@limiter.limit(
    "5/minute"
)
@limiter.limit(
    "5/minute",
    key_func=get_otp_account_limit_key,
)
def request_otp():
    """
    Generate a step-up authentication OTP.

    SECURITY:
    Phone identifiers are canonicalized before rate limiting. OTP generation
    uses a cryptographically secure random source, and plaintext OTP values
    must never be written to logs.
    """
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    raw_phone = data.get(
        "phone"
    )

    try:
        phone = normalize_phone(
            raw_phone
        )

    except ValueError:
        return jsonify({
            "error": (
                "valid phone number required"
            )
        }), 400

    otp = (
        f"{secrets.randbelow(900_000) + 100_000:06d}"
    )

    # FUNCTIONALITY:
    # The production SMS integration belongs here.
    #
    # SECURITY:
    # Persist only a hash of the OTP, give it a short expiration and enforce
    # single-use/attempt limits. Never log the plaintext OTP.
    #
    # Example:
    # otp_hash = hashlib.sha256(
    #     otp.encode("utf-8")
    # ).hexdigest()

    return jsonify({
        "status": "otp_sent",
        "phone": phone,
    })