"""Signed-session security regression tests."""

from datetime import datetime, timezone, timedelta

from itsdangerous import URLSafeTimedSerializer


SESSION_SALT = "sentinelpay-session"


def test_tampered_session_is_rejected(
    client,
    admin_auth_headers,
    monkeypatch,
):
    key = "unit-test-session-signing-key"

    serializer = URLSafeTimedSerializer(
        key,
        salt=SESSION_SALT,
    )

    signed = serializer.dumps(
        {
            "user_id": 1,
            "role": "admin",
        }
    )

    # Modify the signed payload without recomputing the signature.
    tampered = signed[:-1] + (
        "A" if signed[-1] != "A" else "B"
    )

    monkeypatch.setenv(
        "SESSION_SIGNING_KEY",
        key,
    )

    response = client.post(
        "/v1/admin/session/restore",
        headers=admin_auth_headers,
        json={
            "session": tampered,
        },
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid session"


def test_valid_signed_session_is_accepted(
    client,
    admin_auth_headers,
):
    serializer = URLSafeTimedSerializer(
        "unit-test-session-signing-key",
        salt=SESSION_SALT,
    )

    signed = serializer.dumps(
        {
            "user_id": 1,
            "role": "admin",
        }
    )

    response = client.post(
        "/v1/admin/session/restore",
        headers=admin_auth_headers,
        json={
            "session": signed,
        },
    )

    assert response.status_code == 200
    assert response.get_json()["restored"] is True


def test_expired_session_is_rejected(
    client,
    admin_auth_headers,
    monkeypatch,
):
    serializer = URLSafeTimedSerializer(
        "unit-test-session-signing-key",
        salt=SESSION_SALT,
    )

    signed = serializer.dumps(
        {
            "user_id": 1,
            "role": "admin",
        }
    )

    monkeypatch.setattr(
        "time.time",
        lambda: datetime.now(timezone.utc).timestamp() + 7200,
    )

    response = client.post(
        "/v1/admin/session/restore",
        headers=admin_auth_headers,
        json={
            "session": signed,
        },
    )

    assert response.status_code == 400