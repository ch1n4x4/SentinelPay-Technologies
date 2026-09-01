import json
import logging
from datetime import datetime, timezone, timedelta

import jwt
import pytest


# ============================================================================
# V-APP-01: SQL INJECTION (CWE-89)
# ============================================================================
def test_v_app_01_sqli_kyc_lookup(client, user_1_header):
    """
    Ensure the KYC lookup endpoint safely parameterizes the BVN/NIN query string.
    A malicious payload should be treated as literal data, preventing syntax manipulation.
    """
    malicious_payload = "' OR 1=1 --"
    
    response = client.get(
        "/v1/verify/lookup",
        headers=user_1_header,
        query_string={"bvn": malicious_payload}
    )
    
    # A secure parameterized query will simply find no matching records and return 200 OK with an empty list.
    # A vulnerable implementation might throw a 500 syntax error or return other users' records.
    assert response.status_code == 200
    assert response.get_json() == []


# ============================================================================
# V-APP-02: BROKEN JWT VALIDATION (CWE-347)
# ============================================================================
def test_v_app_02_jwt_alg_none_rejected(client):
    """
    Ensure KYC JWT verification rejects the 'alg: none' bypass mechanism.
    """
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "user_id": 3,
        "role": "merchant",
        "exp": (datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()
    }
    
    b64_header = jwt.utils.base64url_encode(json.dumps(header).encode()).decode()
    b64_payload = jwt.utils.base64url_encode(json.dumps(payload).encode()).decode()
    unsigned_token = f"{b64_header}.{b64_payload}."
    
    response = client.get(
        "/v1/verify/lookup?nin=12345678901",
        headers={"Authorization": f"Bearer {unsigned_token}"}
    )
    
    assert response.status_code == 401


def test_v_app_02_jwt_hs256_rejected(client):
    """
    Ensure the KYC service strictly requires RS256 asymmetric signatures and rejects
    tokens signed with symmetric algorithms (HS256) even if the secret matches a public key.
    """
    payload = {"user_id": 3, "role": "merchant"}
    token = jwt.encode(payload, "attacker_controlled_secret", algorithm="HS256")
    
    response = client.get(
        "/v1/verify/lookup?nin=12345678901",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 401


# ============================================================================
# V-APP-03: INSECURE DIRECT OBJECT REFERENCE (CWE-639)
# ============================================================================
def test_v_app_03_idor_document_retrieval(client, user_1_header):
    """
    Ensure users cannot read KYC documents belonging to other customers.
    The S3 key prefix must be bound to the authenticated user ID.
    """
    # Attempting to fetch a document belonging to User 4 using User 1's token
    target_user_id = 4
    malicious_key = f"users/{target_user_id}/passport.pdf"
    
    response = client.get(
        f"/v1/documents/{malicious_key}",
        headers=user_1_header
    )
    
    # Must be blocked securely (403 Forbidden or 404 Not Found)
    assert response.status_code in (403, 404)


# ============================================================================
# V-APP-04: SERVER-SIDE REQUEST FORGERY (CWE-918)
# ============================================================================
@pytest.mark.parametrize("malicious_provider_url", [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1:8001/v1/admin/users",
    "http://localhost:6379",
    "file:///etc/passwd"
])
def test_v_app_04_ssrf_bvn_provider_lookup(client, user_1_header, malicious_provider_url):
    """
    Ensure the BVN verification endpoint relies on server-side configurations
    and rejects arbitrary attacker-controlled provider URLs.
    """
    response = client.post(
        "/v1/verify/bvn",
        headers=user_1_header,
        json={
            "bvn": "22134567890",
            "provider": malicious_provider_url
        }
    )
    
    # A secure implementation uses the provider parameter as a dictionary key, 
    # failing cleanly on unknown/injected values.
    assert response.status_code == 400


# ============================================================================
# V-APP-09: VERBOSE ERROR RESPONSES (CWE-209)
# ============================================================================
def test_v_app_09_no_stack_traces_in_kyc_errors(client, user_1_header):
    """
    Ensure unhandled exceptions in the KYC service do not leak stack traces to the client.
    """
    response = client.get(
        "/v1/documents/invalid/path/that/causes/exception",
        headers=user_1_header
    )
    
    response_text = response.get_data(as_text=True).lower()
    
    assert "traceback" not in response_text
    assert "file \"" not in response_text
    assert "boto3" not in response_text


# ============================================================================
# V-APP-11: MISSING AUDIT LOGGING (CWE-778)
# ============================================================================
def test_v_app_11_audit_logging_kyc_status_change(client, admin_auth_headers, caplog):
    """
    Ensure sensitive administrative actions, such as changing a KYC verification 
    status, emit a structured audit log.
    """
    caplog.set_level(logging.INFO, logger="sentinelpay.audit")
    
    record_id = 1
    new_status = "verified"
    
    response = client.put(
        f"/v1/verify/{record_id}/status",
        headers=admin_auth_headers,
        json={"status": new_status}
    )
    
    assert response.status_code == 200
    
    audit_events = []
    for record in caplog.records:
        if record.name == "sentinelpay.audit":
            try:
                audit_events.append(json.loads(record.message))
            except json.JSONDecodeError:
                pass
                
    # Verify the event contains the target and actor details
    assert any(
        event.get("event") == "kyc_status_change" 
        and event.get("target") == f"kyc_record:{record_id}"
        and event.get("new_status") == new_status
        for event in audit_events
    ), "Structured audit log for kyc_status_change was not properly emitted."