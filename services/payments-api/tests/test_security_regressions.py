import json
import logging
import pickle
import base64
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import jwt
import pytest


# ============================================================================
# V-APP-01: SQL INJECTION (CWE-89)
# ============================================================================
def test_v_app_01_sqli_transaction_search(client, user_1_header):
    """
    Ensure the transaction lookup endpoint does not concatenate user input into raw SQL.
    A malicious payload should be treated safely as a literal string.
    """
    malicious_payload = "' OR 1=1 --"
    
    response = client.get(
        "/v1/transactions/search",
        headers=user_1_header,
        query_string={"q": malicious_payload}
    )
    
    # If vulnerable, this might throw a 500 (syntax error) or return all DB records.
    # A secure implementation parameterizes the input and returns 200 (likely an empty list).
    assert response.status_code == 200
    
    # Ensure invalid types aren't pushed directly into SQL
    response_type_error = client.get(
        "/v1/transactions/search",
        headers=user_1_header,
        query_string={"account_id": malicious_payload}
    )
    assert response_type_error.status_code == 400


# ============================================================================
# V-APP-02: BROKEN JWT VALIDATION (CWE-347)
# ============================================================================
def test_v_app_02_jwt_alg_none_rejected(client):
    """
    Ensure JWT verification strictly rejects the 'alg: none' bypass.
    """
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "user_id": 1,
        "role": "admin",
        "exp": (datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()
    }
    
    # Manually construct an unsigned JWT
    b64_header = jwt.utils.base64url_encode(json.dumps(header).encode()).decode()
    b64_payload = jwt.utils.base64url_encode(json.dumps(payload).encode()).decode()
    unsigned_token = f"{b64_header}.{b64_payload}."
    
    response = client.get(
        "/v1/accounts/",
        headers={"Authorization": f"Bearer {unsigned_token}"}
    )
    
    assert response.status_code == 401


def test_v_app_02_jwt_hs256_rejected(client):
    """
    Ensure the application rejects symmetric (HS256) signatures if it is 
    configured to strictly expect asymmetric (RS256) signatures.
    """
    payload = {"user_id": 1, "role": "admin"}
    # Sign with a random symmetric secret
    token = jwt.encode(payload, "weak_secret_key", algorithm="HS256")
    
    response = client.get(
        "/v1/accounts/",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 401


# ============================================================================
# V-APP-03: INSECURE DIRECT OBJECT REFERENCE (CWE-639)
# ============================================================================
def test_v_app_03_idor_account_access(client, user_1_header):
    """
    Ensure an account endpoint does not serve an account ID without an ownership check.
    User 1 should not be able to read or modify User 2's account (ID: 5).
    """
    target_account_id = 5 
    
    response_read = client.get(
        f"/v1/accounts/{target_account_id}",
        headers=user_1_header
    )
    # The application must refuse access (403 Forbidden or 404 Not Found)
    assert response_read.status_code in (403, 404)


# ============================================================================
# V-APP-04: SERVER-SIDE REQUEST FORGERY (CWE-918)
# ============================================================================
@pytest.mark.parametrize("malicious_url", [
    "http://127.0.0.1:8001/health",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO"
])
def test_v_app_04_ssrf_webhook_validation(client, user_1_header, malicious_url):
    """
    Ensure webhook callback URLs are strictly validated for scheme and destination.
    Internal IP ranges and non-HTTPS schemes must be rejected.
    """
    response = client.post(
        "/v1/webhooks/test",
        headers=user_1_header,
        json={"url": malicious_url}
    )
    
    # Must be blocked by input validation prior to execution
    assert response.status_code == 400


# ============================================================================
# V-APP-05: WALLET RACE CONDITION (CWE-362)
# ============================================================================
def test_v_app_05_wallet_race_condition(client_factory, user_1_header):
    """
    Ensure debit operations utilize row-level locks (e.g., SELECT ... FOR UPDATE).
    Concurrent requests exceeding the total balance must not result in a negative balance.
    """
    account_id = 3
    debit_amount = Decimal("150000.00") # Assume balance is large enough for one, but not two
    
    def attempt_debit():
        # Create an isolated client per thread
        client = client_factory()
        return client.post(
            f"/v1/wallets/{account_id}/debit",
            headers=user_1_header,
            json={"amount": str(debit_amount), "description": "Race condition test"}
        )

    # Fire two concurrent debit requests
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: attempt_debit(), range(2)))

    status_codes = sorted([resp.status_code for resp in responses])
    
    # If properly locked, one request succeeds (200), the second must fail (400 - insufficient funds)
    # If vulnerable to a race condition, both might return 200
    assert status_codes == [200, 400]


# ============================================================================
# V-APP-06: WEAK PASSWORD HASHING (CWE-916)
# ============================================================================
def test_v_app_06_strong_password_hashing():
    """
    Ensure new passwords are not stored using un-salted MD5.
    They must be hashed using a strong, work-factored algorithm like Argon2.
    """
    from app.auth import hash_password 
    
    plaintext = "SecurePassword123!"
    hashed = hash_password(plaintext)
    
    # Ensure it's not a 32-character raw MD5 hash
    assert len(hashed) != 32
    # Ensure it utilizes Argon2 (standard format starts with $argon2id$)
    assert hashed.startswith("$argon2id$")


# ============================================================================
# V-APP-07: MASS ASSIGNMENT (CWE-915)
# ============================================================================
def test_v_app_07_mass_assignment_profile_update(client, user_1_header):
    """
    Ensure user profile update endpoints do not blindly bind the raw request 
    body to the ORM model, protecting critical fields like `balance` or `role`.
    """
    response = client.put(
        "/v1/accounts/3/profile",
        headers=user_1_header,
        json={"currency": "USD", "balance": 99999999.00}
    )
    
    # The application should reject requests containing protected fields
    assert response.status_code == 400
    
    error_msg = response.get_json().get("error", "").lower()
    assert "unsupported" in error_msg or "invalid" in error_msg


# ============================================================================
# V-APP-08: MISSING RATE LIMITING (CWE-307)
# ============================================================================
def test_v_app_08_login_rate_limiting(client):
    """
    Ensure critical endpoints (login, OTP) enforce rate limiting to prevent 
    brute-force and credential stuffing attacks.
    """
    statuses = []
    
    # Send requests exceeding the typical bucket size (e.g., 5/minute)
    for _ in range(10):
        response = client.post(
            "/v1/auth/login",
            json={"email": "attacker@example.com", "password": "wrong"}
        )
        statuses.append(response.status_code)
        
    # At least one request must hit the 429 Too Many Requests limit
    assert 429 in statuses


# ============================================================================
# V-APP-09: VERBOSE ERROR RESPONSES (CWE-209)
# ============================================================================
def test_v_app_09_no_stack_traces_in_errors(client, user_1_header, monkeypatch):
    """
    Ensure API error responses do not leak stack traces or internal implementation details.
    """
    # Force an unhandled exception by passing bad data types
    response = client.get(
        "/v1/transactions/search",
        headers=user_1_header,
        query_string={"account_id": "invalid_string_causes_exception"}
    )
    
    response_text = response.get_data(as_text=True).lower()
    
    # Ensure verbose exception keywords are sanitized out of the client response
    assert "traceback (most recent call last)" not in response_text
    assert "file \"" not in response_text
    assert "line " not in response_text
    assert "exception" not in response_text


# ============================================================================
# V-APP-10: INSECURE DESERIALISATION (CWE-502)
# ============================================================================
def test_v_app_10_insecure_deserialisation_rejected(client, admin_auth_headers):
    """
    Ensure session payloads are not evaluated using raw `pickle`. 
    The endpoint must validate integrity via signatures (like itsdangerous).
    """
    # Create a malicious raw pickle payload
    class MaliciousPayload:
        def __reduce__(self):
            import os
            return (os.system, ('echo "Hacked"',))
            
    malicious_pickle = base64.b64encode(pickle.dumps(MaliciousPayload())).decode("utf-8")
    
    response = client.post(
        "/v1/admin/session/restore",
        headers=admin_auth_headers,
        json={"session": malicious_pickle}
    )
    
    # The application should fail safely (400 Bad Request) due to missing cryptographic signature
    assert response.status_code == 400


# ============================================================================
# V-APP-11: MISSING AUDIT LOGGING (CWE-778)
# ============================================================================
def test_v_app_11_structured_audit_logging(client, user_1_header, caplog):
    """
    Ensure sensitive operations emit structured audit logs.
    """
    # Hook into the audit logger
    caplog.set_level(logging.INFO, logger="sentinelpay.audit")
    
    # Perform a sensitive operation
    response = client.post(
        "/v1/wallets/3/credit",
        headers=user_1_header,
        json={"amount": "100.00", "description": "Audit trail test"}
    )
    
    assert response.status_code == 200
    
    # Search the captured log records for the expected JSON structure
    audit_events = []
    for record in caplog.records:
        if record.name == "sentinelpay.audit":
            try:
                audit_events.append(json.loads(record.message))
            except json.JSONDecodeError:
                pass
                
    # Verify the specific event was logged with context
    assert any(
        event.get("event") == "wallet_credit" and event.get("account_id") == 3
        for event in audit_events
    ), "Structured audit log for wallet_credit was not emitted."