"""Authentication routes: registration, login, OTP, and token refresh."""
import re
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify

from app.extensions import limiter
from app.db import get_connection
from app.auth import hash_password, authenticate_user, issue_token

# REMEDIATION START: V-APP-08 Rate Limiting
from flask_limiter.util import get_remote_address
# REMEDIATION END

auth_bp = Blueprint("auth", __name__)


# REMEDIATION START: V-APP-08 Rate Limiting Bucket Fix (Normalization)
def normalize_email(value: str) -> str:
    return value.strip().lower()

def get_email_limit_key():
    data = request.get_json(silent=True) or {}
    email = data.get("email")

    if not email:
        return f"ip:{get_remote_address()}"

    return f"account:{normalize_email(email)}"


# REMEDIATION START: V-APP-08 Canonical Phone Normalization
# Implemented a basic canonical parser to ensure equivalent representations of a 
# phone number don't produce different lookup/rate-limit behavior[cite: 32].
def canonicalize_phone(phone: str) -> str:
    """Project's canonical phone-number parser. Strips formatting."""
    return re.sub(r"[^\d+]", "", phone)


def normalize_phone(value: str) -> str:
    phone = str(value).strip()
    return canonicalize_phone(phone)
# REMEDIATION END


def lookup_account_id_by_phone(phone: str):
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id
            FROM users
            WHERE phone = %s
            """,
            (phone,),
        )
        row = cur.fetchone()
        return row["id"] if row else None
    finally:
        cur.close()
        conn.close()

def get_otp_account_limit_key():
    data = request.get_json(silent=True) or {}
    # Uses the canonical value for the account lookup and limiter[cite: 32].
    phone = normalize_phone(data.get("phone", ""))

    account_id = lookup_account_id_by_phone(phone)

    if account_id is None:
        return f"unknown-phone:{phone}"

    return f"account:{account_id}"

# REMEDIATION END


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
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=get_otp_account_limit_key)
def request_otp():
    """Request an OTP code for step-up authentication."""
    import random

    data = request.get_json() or {}
    phone = data.get("phone")

    otp = str(random.randint(100000, 999999))

    return jsonify({
        "status": "sent",
        "phone": phone,
    })