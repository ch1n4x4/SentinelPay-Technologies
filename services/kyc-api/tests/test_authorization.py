"""KYC authorization regression tests."""


def test_user_cannot_read_another_users_document(
    client,
    user_1_header,
):
    other_user_id = 4

    response = client.get(
        f"/v1/documents/users/{other_user_id}/passport.pdf",
        headers=user_1_header,
    )

    assert response.status_code in (403, 404)


def test_non_admin_cannot_change_kyc_status(
    client,
    user_1_header,
):
    response = client.put(
        "/v1/verify/1/status",
        headers=user_1_header,
        json={
            "status": "verified",
        },
    )

    assert response.status_code == 403


def test_admin_can_change_kyc_status(
    client,
    admin_auth_headers,
):
    response = client.put(
        "/v1/verify/1/status",
        headers=admin_auth_headers,
        json={
            "status": "verified",
        },
    )

    assert response.status_code == 200