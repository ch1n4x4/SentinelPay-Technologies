"""JWT security regression tests."""

from datetime import datetime, timedelta, timezone

import jwt


def test_alg_none_is_rejected(app):
    header = {
        "alg": "none",
        "typ": "JWT",
    }

    payload = {
        "user_id": 3,
        "role": "admin",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    token = (
        jwt.utils.base64url_encode(
            jwt.api_jws.json_encode(header)
        ).decode()
        + "."
        + jwt.utils.base64url_encode(
            jwt.api_jws.json_encode(payload)
        ).decode()
        + "."
    )

    client = app.test_client()

    response = client.get(
        "/v1/accounts/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_hs256_token_is_rejected(app, rsa_public_key):
    payload = {
        "user_id": 3,
        "role": "admin",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    token = jwt.encode(
        payload,
        "attacker-controlled-secret",
        algorithm="HS256",
    )

    client = app.test_client()

    response = client.get(
        "/v1/accounts/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_expired_token_is_rejected(app, private_key):
    payload = {
        "user_id": 3,
        "role": "merchant",
        "iat": datetime.now(timezone.utc) - timedelta(hours=1),
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )

    client = app.test_client()

    response = client.get(
        "/v1/accounts/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_missing_exp_is_rejected(app, private_key):
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

    client = app.test_client()

    response = client.get(
        "/v1/accounts/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_missing_iat_is_rejected(app, private_key):
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

    client = app.test_client()

    response = client.get(
        "/v1/accounts/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_valid_rs256_token_is_accepted(app, private_key):
    payload = {
        "user_id": 3,
        "role": "merchant",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )

    client = app.test_client()

    response = client.get(
        "/v1/accounts/",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200