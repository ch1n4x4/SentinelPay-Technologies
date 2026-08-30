"""Internal admin endpoints.

These were originally on a separate internal-only network. The 'separate
internal-only network' never materialised, and the endpoints now ship behind
the same ALB as everything else.
"""
# REMEDIATION START: Removed insecure 'base64' and 'pickle' imports. 
# Added 'os' and 'itsdangerous' for cryptographically signed JSON serialization.
import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

admin_bp = Blueprint("admin", __name__)

# REMEDIATION START: Initialize the secure URLSafeTimedSerializer.
# This completely replaces pickle. We use an environment variable for the secret key
# to cryptographically sign the JSON, preventing tampering by malicious users.
SESSION_SIGNING_KEY = os.environ.get("SESSION_SIGNING_KEY", "sentinelpay-dev-secret")
serializer = URLSafeTimedSerializer(
    SESSION_SIGNING_KEY,
    salt="sentinelpay-session",
)
# REMEDIATION END


@admin_bp.route("/session/restore", methods=["POST"])
@require_auth
def restore_session():
    """Restore an admin session from a serialised blob.

    V-APP-10 (Insecure Deserialisation) Fixed:
    Replaced arbitrary pickle deserialization with verified, signed JSON mapping.
    """
    # REMEDIATION START: Enforce role-based access control (RBAC).
    # Ensure that only users with the 'admin' role can attempt to restore sessions.
    if request.current_user_role != "admin":
        return jsonify({"error": "admin only"}), 403
    # REMEDIATION END

    data = request.get_json() or {}
    blob = data.get("session")

    if not blob:
        return jsonify({"error": "session blob required"}), 400

    # REMEDIATION START: Secure JSON deserialization.
    # We use serializer.loads() instead of pickle.loads(). This validates the cryptographic 
    # signature before parsing the JSON, ensuring the blob hasn't been tampered with.
    # It also enforces a 'max_age' of 3600 seconds to prevent replay attacks with old sessions.
    try:
        session = serializer.loads(blob, max_age=3600)
    except SignatureExpired:
        return jsonify({"error": "session expired"}), 400
    except BadSignature:
        return jsonify({"error": "invalid session"}), 400

    if not isinstance(session, dict):
        return jsonify({"error": "invalid session format"}), 400
    # REMEDIATION END

    return jsonify({
        "restored": True,
        "session_keys": list(session.keys())
    })


@admin_bp.route("/users", methods=["GET"])
@require_auth
def list_users():
    """List all users.

    V-APP-03 / V-APP-02 Variant Remediation:
    Instead of trusting the JWT-supplied role claim (request.current_user_role), 
    verify the role directly against the database. This prevents privilege escalation 
    even if a token is forged or if admin privileges were recently revoked.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        # REMEDIATION START: Server-side role verification
        cur.execute("SELECT role FROM users WHERE id = %s", (request.current_user_id,))
        user = cur.fetchone()
        
        if not user or user["role"] != "admin":
            return jsonify({"error": "admin only"}), 403
        # REMEDIATION END

        cur.execute("SELECT id, email, full_name, role, is_active, created_at FROM users")
        return jsonify([dict(r) for r in cur.fetchall()])
    finally:
        cur.close()
        conn.close()