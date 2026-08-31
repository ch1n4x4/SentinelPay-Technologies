"""IDOR / object-authorization regression tests."""

USER_1_ACCOUNT_ID = 3
USER_2_ACCOUNT_ID = 5
USER_2_TRANSACTION_REFERENCE = "TXN-2026-004"


def test_user_cannot_read_another_users_account(
    client,
    user_1_header,
):
    response = client.get(
        f"/v1/accounts/{USER_2_ACCOUNT_ID}",
        headers=user_1_header,
    )

    assert response.status_code in (403, 404)


def test_user_cannot_update_another_users_account(
    client,
    user_1_header,
):
    response = client.put(
        f"/v1/accounts/{USER_2_ACCOUNT_ID}/profile",
        headers=user_1_header,
        json={
            "currency": "USD",
        },
    )

    assert response.status_code in (403, 404)


def test_user_cannot_read_another_users_transaction(
    client,
    user_1_header,
):
    response = client.get(
        f"/v1/transactions/{USER_2_TRANSACTION_REFERENCE}",
        headers=user_1_header,
    )

    assert response.status_code in (403, 404)


def test_user_cannot_credit_another_users_account(
    client,
    user_1_header,
):
    response = client.post(
        f"/v1/wallets/{USER_2_ACCOUNT_ID}/credit",
        headers=user_1_header,
        json={
            "amount": "100.00",
            "description": "IDOR regression",
        },
    )

    assert response.status_code in (403, 404)


def test_user_cannot_debit_another_users_account(
    client,
    user_1_header,
):
    response = client.post(
        f"/v1/wallets/{USER_2_ACCOUNT_ID}/debit",
        headers=user_1_header,
        json={
            "amount": "50.00",
            "description": "IDOR regression",
        },
    )

    assert response.status_code in (403, 404)


def test_non_admin_cannot_access_admin_user_list(
    client,
    user_1_header,
):
    response = client.get(
        "/v1/admin/users",
        headers=user_1_header,
    )

    assert response.status_code == 403