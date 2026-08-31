"""Identity verification endpoints."""
import os
import requests
from flask import Blueprint, request, jsonify, current_app

from app.db import get_connection
from app.auth import require_auth
from app.audit import audit_event

verify_bp = Blueprint("verify", __name__)

PROVIDERS = {
    "cbn": os.environ.get("BVN_CBN_URL", "https://api.mock-cbn.local/bvn"),
    "provider_ng": os.environ.get("BVN_PROVIDER_NG_URL", "https://api.mock-provider-ng.local/bvn"),
}


@verify_bp.route("/bvn", methods=["POST"])
@require_auth
def verify_bvn():
    """Verify a BVN against the upstream lookup service."""
    data = request.get_json() or {}
    bvn = data.get("bvn")
    
    provider = data.get("provider", "cbn")
    
    if provider not in PROVIDERS:
        return jsonify({"error": "unsupported provider"}), 400
        
    provider_url = PROVIDERS[provider]

    if not bvn or len(bvn) != 11:
        return jsonify({"error": "valid 11-digit BVN required"}), 400

    try:
        resp = requests.post(
            provider_url, 
            json={"bvn": bvn}, 
            timeout=10,
            allow_redirects=False
        )
        return jsonify({"status": "ok", "provider_response": resp.text[:2000]})
    except requests.RequestException:
        current_app.logger.exception("KYC provider request failed")
        return jsonify({"error": "KYC verification failed"}), 502


@verify_bp.route("/lookup", methods=["GET"])
@require_auth
def lookup_kyc():
    """Look up a KYC record by BVN or NIN."""
    bvn = request.args.get("bvn", "")
    nin = request.args.get("nin", "")

    if not bvn and not nin:
        return jsonify({"error": "bvn or nin required"}), 400

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
            params = (bvn, request.current_user_id)
        else:
            query = """
                SELECT *
                FROM kyc_records
                WHERE nin = %s
                AND user_id = %s
            """
            params = (nin, request.current_user_id)

        cur.execute(query, params)
        records = cur.fetchall()

        return jsonify([dict(r) for r in records])

    finally:
        cur.close()
        conn.close()


@verify_bp.route("/<int:record_id>/status", methods=["PUT"])
@require_auth
def update_kyc_status(record_id):
    """Update the status of a KYC record and log the event."""
    
    # REMEDIATION START: V-APP-03 KYC Status Authorization Check
    # Changing a KYC status is a privileged operation. We enforce an admin role 
    # check here to ensure users cannot self-approve their own KYC documents.
    if request.current_user_role != "admin":
        return jsonify({"error": "admin only"}), 403
    # REMEDIATION END

    data = request.get_json() or {}
    new_status = data.get("status")
    
    if not new_status:
        return jsonify({"error": "status required"}), 400
        
    conn = get_connection()
    cur = conn.cursor()
    try:
        # REMEDIATION START: V-APP-03 Server-Side Role Verification
        # Verify the role from the database rather than blindly trusting the JWT claim[cite: 37].
        cur.execute(
            "SELECT role FROM users WHERE id = %s",
            (request.current_user_id,)
        )
        user = cur.fetchone()
        
        if not user or user["role"] != "admin":
            return jsonify({"error": "admin only"}), 403
        # REMEDIATION END

        cur.execute("SELECT status FROM kyc_records WHERE id = %s", (record_id,))
        row = cur.fetchone()
        
        if not row:
            return jsonify({"error": "record not found"}), 404
            
        old_status = row["status"]
        
        cur.execute("UPDATE kyc_records SET status = %s WHERE id = %s", (new_status, record_id))
        conn.commit()
        
        audit_event(
            "kyc_status_change",
            actor_user_id=request.current_user_id,
            action="kyc_status_change",
            target=f"kyc_record:{record_id}",
            old_status=old_status,
            new_status=new_status,
        )
        
        return jsonify({"status": "updated"})
    finally:
        cur.close()
        conn.close()