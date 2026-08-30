"""Identity verification endpoints."""
import os
import requests
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

verify_bp = Blueprint("verify", __name__)

# REMEDIATION START: SSRF Partial Remediation (V-APP-05 Variant)
# Map identifiers to preconfigured URLs rather than allowing the caller 
# to select arbitrary provider URLs[cite: 16].
PROVIDERS = {
    "cbn": os.environ.get("BVN_CBN_URL", "https://api.mock-cbn.local/bvn"),
    "provider_ng": os.environ.get("BVN_PROVIDER_NG_URL", "https://api.mock-provider-ng.local/bvn"),
}
# REMEDIATION END


@verify_bp.route("/bvn", methods=["POST"])
@require_auth
def verify_bvn():
    """Verify a BVN against the upstream lookup service."""
    data = request.get_json() or {}
    bvn = data.get("bvn")
    
    # REMEDIATION START: SSRF Strict Allowlisting
    # Validate the provider string against the PROVIDERS dictionary.
    # Never accept a raw URL from the request[cite: 16].
    provider = data.get("provider", "cbn")
    
    if provider not in PROVIDERS:
        return jsonify({"error": "unsupported provider"}), 400
        
    provider_url = PROVIDERS[provider]
    # REMEDIATION END

    if not bvn or len(bvn) != 11:
        return jsonify({"error": "valid 11-digit BVN required"}), 400

    try:
        # REMEDIATION START: SSRF Redirect Prevention
        # Add allow_redirects=False to prevent the upstream server from 
        # redirecting the request to a local/reserved IP address[cite: 16].
        resp = requests.post(
            provider_url, 
            json={"bvn": bvn}, 
            timeout=10,
            allow_redirects=False
        )
        # REMEDIATION END
        
        return jsonify({"status": "ok", "provider_response": resp.text[:2000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

"""V-APP-01 (SQLi) Fixed:
Parameterize all values
"""
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
            query = "SELECT * FROM kyc_records WHERE bvn = %s"
            params = (bvn,)
        else:
            query = "SELECT * FROM kyc_records WHERE nin = %s"
            params = (nin,)

        cur.execute(query, params)
        records = cur.fetchall()

        return jsonify([dict(r) for r in records])

    finally:
        cur.close()
        conn.close()