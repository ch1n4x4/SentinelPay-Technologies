"""IDOR / authorization regression tests.

These tests verify that an authenticated user cannot access or modify
another user's resources.
"""

import pytest


USER_A = {
    "id": 3,
    "email": "merchant1@example.com",
    "account_id": 3,
    "transaction_reference": "TXN-2026-001",
}

USER_B = {
    "id": 4,
    "email": "merchant2@example.com",
    "account_id": 5,
}


@pytest.fixture
def user_a_client(app):
    return app.test_client()


@pytest.fixture
def user_b_client(app):
    return app.test_client()


def test_user_b_cannot_read_user_a_account(
    user_b_client,
    user_b_auth_headers,
):
    response = user_b_client.get(
        f"/v1/accounts/{USER_A['account_id']}",
        headers=user_b_auth_headers,
    )

    assert response.status_code in (403, 404)


def test_user_b_cannot_update_user_a_account(
    user_b_client,
    user_b_auth_headers,
):
    response = user_b_client.put(
        f"/v1/accounts/{USER_A['account_id']}/profile",
        headers=user_b_auth_headers,
        json={"currency": "USD"},
    )

    assert response.status_code in (403, 404)


def test_user_b_cannot_debit_user_a_account(
    user_b_client,
    user_b_auth_headers,
):
    response = user_b_client.post(
        f"/v1/wallets/{USER_A['account_id']}/debit",
        headers=user_b_auth_headers,
        json={
            "amount": "1.00",
            "description": "IDOR regression",
        },
    )

    assert response.status_code in (403, 404)


def test_user_b_cannot_credit_user_a_account(
    user_b_client,
    user_b_auth_headers,
):
    response = user_b_client.post(
        f"/v1/wallets/{USER_A['account_id']}/credit",
        headers=user_b_auth_headers,
        json={
            "amount": "1.00",
            "description": "IDOR regression",
        },
    )

    assert response.status_code in (403, 404)


def test_user_b_cannot_read_user_a_transaction(
    user_b_client,
    user_b_auth_headers,
):
    response = user_b_client.get(
        f"/v1/transactions/{USER_A['transaction_reference']}",
        headers=user_b_auth_headers,
    )

    assert response.status_code in (403, 404)


def test_non_admin_cannot_change_kyc_status(
    user_b_client,
    user_b_auth_headers,
):
    response = user_b_client.put(
        "/v1/verify/1/status",
        headers=user_b_auth_headers,
        json={"status": "verified"},
    )

    assert response.status_code == 403