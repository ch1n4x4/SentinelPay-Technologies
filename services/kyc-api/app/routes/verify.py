"""Identity verification endpoints."""

import os

import requests

from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
)

from app.db import get_connection
from app.auth import require_auth
from app.audit import audit_event


verify_bp = Blueprint(
    "verify",
    __name__,
)


# ============================================================================
# BVN PROVIDER CONFIGURATION
# ============================================================================
#
# REMEDIATION V-APP-05:
# The caller supplies only a provider name. The actual destination URL is
# controlled by server-side configuration, eliminating arbitrary outbound URL
# selection by the request.
PROVIDERS = {
    "cbn": os.environ.get(
        "BVN_CBN_URL",
        "https://api.mock-cbn.local/bvn",
    ),
    "provider_ng": os.environ.get(
        "BVN_PROVIDER_NG_URL",
        "https://api.mock-provider-ng.local/bvn",
    ),
}


@verify_bp.route(
    "/bvn",
    methods=["POST"],
)
@require_auth
def verify_bvn():
    """
    Verify a BVN against an approved upstream provider.
    """
    data = (
        request.get_json()
        or {}
    )

    bvn = data.get(
        "bvn"
    )

    provider = data.get(
        "provider",
        "cbn",
    )

    if provider not in PROVIDERS:
        return jsonify({
            "error": (
                "unsupported provider"
            )
        }), 400

    provider_url = PROVIDERS[
        provider
    ]

    if (
        not bvn
        or len(bvn) != 11
    ):
        return jsonify({
            "error": (
                "valid 11-digit BVN required"
            )
        }), 400

    try:
        response = requests.post(
            provider_url,
            json={
                "bvn": bvn
            },
            timeout=10,
            allow_redirects=False,
        )

        return jsonify({
            "status": "ok",
            "provider_response": (
                response.text[:2000]
            ),
        })

    except requests.RequestException:
        # V-APP-09:
        # Keep provider/network diagnostics in internal logs only.
        current_app.logger.exception(
            "KYC provider request failed"
        )

        return jsonify({
            "error": (
                "KYC verification failed"
            )
        }), 502


@verify_bp.route(
    "/lookup",
    methods=["GET"],
)
@require_auth
def lookup_kyc():
    """
    Return KYC records owned by the authenticated user.

    REMEDIATION V-APP-01:
    BVN/NIN values are SQL parameters.

    REMEDIATION V-APP-03:
    The authenticated user's ID is included in the predicate, preventing
    arbitrary lookup of another user's KYC record by BVN/NIN.
    """
    bvn = request.args.get(
        "bvn",
        "",
    )

    nin = request.args.get(
        "nin",
        "",
    )

    if (
        not bvn
        and not nin
    ):
        return jsonify({
            "error": (
                "bvn or nin required"
            )
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        if bvn:
            query = """
                SELECT *
                FROM kyc_records
                WHERE bvn = %s
                  AND user_id = %s
            """

            params = (
                bvn,
                request.current_user_id,
            )

        else:
            query = """
                SELECT *
                FROM kyc_records
                WHERE nin = %s
                  AND user_id = %s
            """

            params = (
                nin,
                request.current_user_id,
            )

        cur.execute(
            query,
            params,
        )

        records = cur.fetchall()

        return jsonify([
            dict(record)
            for record in records
        ])

    finally:
        cur.close()
        conn.close()


@verify_bp.route(
    "/<int:record_id>/status",
    methods=["PUT"],
)
@require_auth
def update_kyc_status(
    record_id,
):
    """
    Change a KYC verification status.

    REMEDIATION V-APP-03:
    This is a privileged operation. The caller must be an admin, and the role is
    checked against the database before the record is changed.

    REMEDIATION V-APP-11:
    Record the actor, target, previous status and new status in the audit log.
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

    new_status = data.get(
        "status"
    )

    if not new_status:
        return jsonify({
            "error": "status required"
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        # SECURITY:
        # Confirm the role against the current database state rather than
        # treating an untrusted role claim as the sole authorization factor.
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

        cur.execute(
            """
            SELECT verification_status
            FROM kyc_records
            WHERE id = %s
            """,
            (record_id,),
        )

        row = cur.fetchone()

        if not row:
            return jsonify({
                "error": "record not found"
            }), 404

        old_status = row[
            "verification_status"
        ]

        cur.execute(
            """
            UPDATE kyc_records
            SET verification_status = %s
            WHERE id = %s
            """,
            (
                new_status,
                record_id,
            ),
        )

        conn.commit()

        audit_event(
            "kyc_status_change",
            actor_user_id=(
                request.current_user_id
            ),
            action="kyc_status_change",
            target=(
                f"kyc_record:{record_id}"
            ),
            old_status=old_status,
            new_status=new_status,
        )

        return jsonify({
            "status": "updated"
        })

    finally:
        cur.close()
        conn.close()