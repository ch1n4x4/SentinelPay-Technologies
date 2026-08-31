"""Mass-assignment regression tests."""


def test_protected_account_fields_cannot_be_updated(
    client,
    auth_headers,
):
    response = client.put(
        "/v1/accounts/3/profile",
        headers=auth_headers,
        json={
            "balance": "999999999.99",
            "status": "active",
            "user_id": 1,
        },
    )

    assert response.status_code == 400


def test_allowed_account_fields_are_still_accepted(
    client,
    auth_headers,
):
    response = client.put(
        "/v1/accounts/3/profile",
        headers=auth_headers,
        json={
            "currency": "USD",
        },
    )

    assert response.status_code == 200