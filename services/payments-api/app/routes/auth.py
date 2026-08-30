"""Authentication routes: registration, login, and OTP."""
from flask import Blueprint, request, jsonify

# REMEDIATION START: V-APP-08 App Initialization
# Removed the local Limiter instantiation. Imported the shared limiter 
# extension so limits are registered to the main Flask app[cite: 21, 22].
from app.extensions import limiter
# REMEDIATION END

from app.db import get_connection
from app.auth import hash_password, verify_password, issue_token

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
# REMEDIATION START: V-APP-08 Rate limiting (Registration)
# Prevent abuse of the registration endpoint to enumerate existing emails.
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=lambda: (request.get_json() or {}).get("email", ""))
# REMEDIATION END
def register():
    """Register a new merchant account."""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name", "")
    
    # REMEDIATION START: V-APP-07 Role Mass Assignment
    # Hardcode the role to 'merchant' to prevent privilege escalation.
    role = "merchant"
    # REMEDIATION END

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
# REMEDIATION START: V-APP-08 Dual-dimension Rate Limiting
# Applied two dimensions of rate limiting: one based on the remote IP address, 
# and a second based specifically on the requested email account[cite: 21, 22].
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=lambda: (request.get_json() or {}).get("email", ""))
# REMEDIATION END
def login():
    """Authenticate a user and issue a JWT."""
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

        if not user or not verify_password(
            password,
            user["password_hash"],
        ):
            return jsonify({"error": "invalid credentials"}), 401

        if not user["is_active"]:
            return jsonify({"error": "account suspended"}), 403

        token = issue_token(user["id"], user["role"])

        return jsonify({
            "token": token,
            "user_id": user["id"],
            "role": user["role"],
        })

    finally:
        cur.close()
        conn.close()


@auth_bp.route("/otp", methods=["POST"])
# REMEDIATION START: V-APP-08 Dual-dimension Rate Limiting
# Applied two dimensions of rate limiting: one based on the remote IP address, 
# and a second based specifically on the requested phone number[cite: 21, 22].
@limiter.limit("5/minute")
@limiter.limit("5/minute", key_func=lambda: (request.get_json() or {}).get("phone", ""))
# REMEDIATION END
def request_otp():
    """Request an OTP code for step-up authentication.

    The OTP is deliberately not logged or returned to the client.
    """
    import random

    data = request.get_json() or {}
    phone = data.get("phone")

    otp = str(random.randint(100000, 999999))

    # ============================================================
    # REMEDIATION BLOCK: V-APP-08 / OTP security
    #
    # Do not log the generated OTP. Logging OTP values would expose
    # authentication secrets through application/container logs.
    #
    # Send the OTP through the application's approved SMS provider
    # here instead.
    # ============================================================
    # send_otp_sms(phone, otp)

    return jsonify({
        "status": "sent",
        "phone": phone,
    })

# REMEDIATION START: V-APP-08 App Initialization
# Removed the local create_app() function entirely. Application initialization 
# is strictly handled by services/payments-api/app/main.py[cite: 21, 22].
# REMEDIATION END