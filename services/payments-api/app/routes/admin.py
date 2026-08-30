"""Internal admin endpoints."""
import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth
from app.audit import audit_event

admin_bp = Blueprint("admin", __name__)

SESSION_SIGNING_KEY = os.environ.get("SESSION_SIGNING_KEY", "sentinelpay-dev-secret")
serializer = URLSafeTimedSerializer(
    SESSION_SIGNING_KEY,
    salt="sentinelpay-session",
)


@admin_bp.route("/session/restore", methods=["POST"])
@require_auth
def restore_session():
    """Restore an admin session from a serialised blob."""
    if request.current_user_role != "admin":
        return jsonify({"error": "admin only"}), 403

    data = request.get_json() or {}
    blob = data.get("session")

    if not blob:
        return jsonify({"error": "session blob required"}), 400

    try:
        session = serializer.loads(blob, max_age=3600)
    except SignatureExpired:
        return jsonify({"error": "session expired"}), 400
    except BadSignature:
        return jsonify({"error": "invalid session"}), 400

    if not isinstance(session, dict):
        return jsonify({"error": "invalid session format"}), 400
        
    # REMEDIATION START: V-APP-11 Admin Audit Logging
    # Emit a structured audit event when an admin session is restored[cite: 27].
    audit_event(
        "session_restore",
        actor_user_id=request.current_user_id,
        action="restore_session",
        target="admin_session",
    )
    # REMEDIATION END

    return jsonify({
        "restored": True,
        "session_keys": list(session.keys())
    })


@admin_bp.route("/users", methods=["GET"])
@require_auth
def list_users():
    """List all users."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT role FROM users WHERE id = %s", (request.current_user_id,))
        user = cur.fetchone()
        
        if not user or user["role"] != "admin":
            return jsonify({"error": "admin only"}), 403
            
        # REMEDIATION START: V-APP-11 Admin Audit Logging
        # Emit a structured audit event when an admin user lists the system users[cite: 27].
        audit_event(
            "admin_user_list",
            actor_user_id=request.current_user_id,
            action="list_users",
            target="users",
        )
        # REMEDIATION END

        cur.execute("SELECT id, email, full_name, role, is_active, created_at FROM users")
        return jsonify([dict(r) for r in cur.fetchall()])
    finally:
        cur.close()
        conn.close()