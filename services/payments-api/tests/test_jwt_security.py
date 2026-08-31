"""JWT security regression tests."""

from datetime import datetime, timedelta, timezone

import jwt


def build_payload(**overrides):
    payload = {
        "user_id": 3,
        "role": "merchant",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    payload.update(overrides)
    return payload


def test_alg_none_is_rejected(client):
    header = {
        "alg": "none",
        "typ": "JWT",
    }

    payload = build_payload()

    unsigned = (
        jwt.utils.base64url_encode(
            jwt.api_jws._jws_encode_json(header)
        ).decode()
        + "."
        + jwt.utils.base64url_encode(
            jwt.api_jws._jws_encode_json(payload)
        ).decode()
        + "."
    )

    response = client.get(
        "/v1/accounts/",
        headers={
            "Authorization": f"Bearer {unsigned}",
        },
    )

    assert response.status_code == 401


def test_hs256_is_rejected(
    client,
):
    token = jwt.encode(
        build_payload(),
        "attacker-controlled-secret",
        algorithm="HS256",
    )

    response = client.get(
        "/v1/accounts/",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401


def test_expired_token_is_rejected(
    client,
    private_key,
):
    token = jwt.encode(
        build_payload(
            iat=datetime.now(timezone.utc) - timedelta(hours=1),
            exp=datetime.now(timezone.utc) - timedelta(minutes=1),
        ),
        private_key,
        algorithm="RS256",
    )

    response = client.get(
        "/v1/accounts/",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401


def test_missing_exp_is_rejected(
    client,
    private_key,
):
    payload = {
        "user_id": 3,
        "role": "merchant",
        "iat": datetime.now(timezone.utc),
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )

    response = client.get(
        "/v1/accounts/",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401


def test_missing_iat_is_rejected(
    client,
    private_key,
):
    payload = {
        "user_id": 3,
        "role": "merchant",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )

    response = client.get(
        "/v1/accounts/",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401


def test_valid_rs256_token_is_accepted(
    client,
    private_key,
):
    token = jwt.encode(
        build_payload(),
        private_key,
        algorithm="RS256",
    )

    response = client.get(
        "/v1/accounts/",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 200


def test_token_cannot_be_used_after_expiry(
    client,
    private_key,
):
    payload = build_payload(
        exp=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )

    response = client.get(
        "/v1/accounts/",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401