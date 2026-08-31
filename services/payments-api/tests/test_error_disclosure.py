"""Error disclosure regression tests."""


def test_invalid_jwt_does_not_disclose_validation_details(
    client,
):
    response = client.get(
        "/v1/accounts/",
        headers={
            "Authorization": (
                "Bearer definitely-invalid-token"
            ),
        },
    )

    assert response.status_code == 401

    body = response.get_json()

    assert body == {
        "error": "unauthorized",
    }

    assert "traceback" not in str(body).lower()
    assert "jwt" not in str(body).lower()
    assert "decode" not in str(body).lower()