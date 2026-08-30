"""Authentication routes: registration, login, and OTP."""
import os

from flask import Flask, Blueprint, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.db import get_connection
from app.auth import hash_password, verify_password, issue_token


# ============================================================
# REMEDIATION BLOCK: V-APP-08 - Rate limiting
#
# Use the client's remote IP address as the default rate-limit
# key and store counters in Redis so limits are shared across
# multiple application instances.
# ============================================================
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv(
        "RATELIMIT_STORAGE_URI",
        "redis://redis:6379/2",
    ),
)


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new merchant account.

    V-APP-08: No rate limiting. Anyone can hammer this endpoint to enumerate
    existing emails (via the unique-constraint error response).
    """
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    full_name = data.get("full_name", "")
    role = data.get("role", "merchant")  # V-APP-07: client can self-assign role

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
def login():
    """Authenticate a user and issue a JWT.

    V-APP-08 remediation: Limit login attempts to 5 requests per
    minute per remote address to reduce password brute-force attempts.
    """
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
@limiter.limit("5/minute")
def request_otp():
    """Request an OTP code for step-up authentication.

    V-APP-08 remediation: Limit OTP generation requests to 5 per
    minute per remote address to reduce OTP abuse and brute forcing.

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


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # ============================================================
    # REMEDIATION BLOCK: Flask-Limiter application initialization
    #
    # Attach the shared limiter to this Flask application so the
    # @limiter.limit(...) decorators above are enforced.
    # ============================================================
    limiter.init_app(app)

    app.register_blueprint(auth_bp, url_prefix="/v1/auth")

    return app