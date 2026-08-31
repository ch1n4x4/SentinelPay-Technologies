"""Authorization and IDOR regression tests for the KYC API."""

def test_user_cannot_read_another_users_document(client, user_1_header, user_2_id):
    """
    Ensure V-APP-03 remediation prevents users from fetching documents outside 
    their designated S3 prefix. Expecting a 404 for anti-enumeration.
    """
    # Attempting to access a document under user_2's directory using user_1's token
    malicious_key = f"users/{user_2_id}/passport.pdf"
    
    response = client.get(
        f"/v1/documents/{malicious_key}", 
        headers=user_1_header
    )
    
    assert response.status_code == 404
    assert response.json.get("error") == "not found"


def test_non_admin_cannot_change_kyc_status(client, merchant_header, kyc_record_id):
    """
    Ensure V-APP-03 remediation prevents standard users from self-approving 
    or modifying KYC records.
    """
    response = client.put(
        f"/v1/verify/{kyc_record_id}/status",
        headers=merchant_header,
        json={"status": "approved"}
    )
    
    assert response.status_code == 403
    assert response.json.get("error") == "admin only"