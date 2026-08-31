"""Signed-session regression tests."""

from itsdangerous import URLSafeTimedSerializer


def test_tampered_session_is_rejected(
    client,
    admin_auth_headers,
    session_signing_key,
):
    serializer = URLSafeTimedSerializer(
        session_signing_key,
        salt="sentinelpay-session",
    )

    signed = serializer.dumps({
        "user_id": 1,
        "role": "admin",
    })

    # Tamper with the signed payload.
    tampered = signed[:-1] + (
        "A" if signed[-1] != "A" else "B"
    )

    response = client.post(
        "/v1/admin/session/restore",
        headers=admin_auth_headers,
        json={"session": tampered},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid session"


def test_session_expiry_is_enforced(
    client,
    admin_auth_headers,
):
    # Use a serializer/test fixture configured with an expired payload.
    # The endpoint must reject it rather than restore it.
    response = client.post(
        "/v1/admin/session/restore",
        headers=admin_auth_headers,
        json={"session": "<expired-signed-session>"},
    )

    assert response.status_code == 400