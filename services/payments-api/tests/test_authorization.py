"""Authorization and IDOR regression tests for the Payments API."""

def test_user_cannot_read_another_users_account(client, user_1_header, user_2_account_id):
    """Ensure a user receives a 404 when attempting to fetch an account they do not own."""
    response = client.get(
        f"/v1/accounts/{user_2_account_id}", 
        headers=user_1_header
    )
    
    assert response.status_code == 404


def test_user_cannot_read_another_users_transaction(client, user_1_header, user_2_transaction_id):
    """Ensure a user cannot access transaction records linked to another user's account."""
    response = client.get(
        f"/v1/transactions/{user_2_transaction_id}", 
        headers=user_1_header
    )
    
    assert response.status_code == 404


def test_user_cannot_credit_another_users_account(client, user_1_header, user_2_account_id):
    """Ensure V-APP-03 remediation prevents crediting arbitrary accounts."""
    response = client.post(
        f"/v1/wallets/{user_2_account_id}/credit",
        headers=user_1_header,
        json={"amount": "100.00"}
    )
    
    assert response.status_code == 404
    assert response.json.get("error") == "account not found"


def test_user_cannot_debit_another_users_account(client, user_1_header, user_2_account_id):
    """Ensure V-APP-03 remediation prevents debiting arbitrary accounts."""
    response = client.post(
        f"/v1/wallets/{user_2_account_id}/debit",
        headers=user_1_header,
        json={"amount": "50.00"}
    )
    
    assert response.status_code == 404
    assert response.json.get("error") == "account not found"