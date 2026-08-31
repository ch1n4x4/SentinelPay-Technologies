"""Internal admin endpoints."""

import os

from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired,
)

from flask import (
    Blueprint,
    request,
    jsonify,
)

from app.db import get_connection
from app.auth import require_auth
from app.audit import audit_event


admin_bp = Blueprint(
    "admin",
    __name__,
)


# ============================================================================
# V-APP-10: SIGNED SESSION CONFIGURATION
# ============================================================================
#
# SECURITY:
# There is no predictable development fallback. Deployment must provide a
# unique signing key through the environment/secret manager.
SESSION_SIGNING_KEY = os.environ[
    "SESSION_SIGNING_KEY"
]


serializer = URLSafeTimedSerializer(
    SESSION_SIGNING_KEY,
    salt="sentinelpay-session",
)


@admin_bp.route(
    "/session/restore",
    methods=["POST"],
)
@require_auth
def restore_session():
    """
    Restore a time-limited signed session.

    REMEDIATION V-APP-10:
    main used pickle deserialization. The test branch accepts a signed,
    time-limited serialization format instead, removing executable pickle
    object deserialization from the request path.
    """
    if (
        request.current_user_role
        != "admin"
    ):
        return jsonify({
            "error": "admin only"
        }), 403

    data = (
        request.get_json()
        or {}
    )

    blob = data.get(
        "session"
    )

    if not blob:
        return jsonify({
            "error": (
                "session blob required"
            )
        }), 400

    try:
        # SECURITY:
        # The payload must have a valid signature and must not be older than
        # one hour.
        session = serializer.loads(
            blob,
            max_age=3600,
        )

    except SignatureExpired:
        return jsonify({
            "error": "session expired"
        }), 400

    except BadSignature:
        return jsonify({
            "error": "invalid session"
        }), 400

    if not isinstance(
        session,
        dict,
    ):
        return jsonify({
            "error": (
                "invalid session format"
            )
        }), 400

    # AUDIT V-APP-11:
    # Session restoration is a privileged administrative action and therefore
    # receives an auditable actor/action/target record.
    audit_event(
        "session_restore",
        actor_user_id=(
            request.current_user_id
        ),
        action="restore_session",
        target="admin_session",
    )

    return jsonify({
        "restored": True,
        "session_keys": list(
            session.keys()
        ),
    })


@admin_bp.route(
    "/users",
    methods=["GET"],
)
@require_auth
def list_users():
    """
    List system users for an administrator.

    SECURITY:
    Authentication proves the identity, while the database role check
    authorizes the privileged operation.
    """
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT role
            FROM users
            WHERE id = %s
            """,
            (
                request.current_user_id,
            ),
        )

        user = cur.fetchone()

        if (
            not user
            or user["role"]
            != "admin"
        ):
            return jsonify({
                "error": "admin only"
            }), 403

        # AUDIT:
        # Record privileged access to the complete user directory.
        audit_event(
            "admin_user_list",
            actor_user_id=(
                request.current_user_id
            ),
            action="list_users",
            target="users",
        )

        cur.execute(
            """
            SELECT
                id,
                email,
                full_name,
                role,
                is_active,
                created_at
            FROM users
            """
        )

        return jsonify([
            dict(row)
            for row in cur.fetchall()
        ])

    finally:
        cur.close()
        conn.close()