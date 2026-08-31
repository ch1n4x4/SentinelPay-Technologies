"""SSRF regression tests."""

from unittest.mock import patch

import pytest

from app.routes.webhooks import validate_callback_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/",
    ],
)
def test_private_or_local_destination_is_rejected(url):
    with pytest.raises(ValueError):
        validate_callback_url(url)


def test_non_https_url_is_rejected():
    with pytest.raises(ValueError):
        validate_callback_url(
            "http://example.com/callback",
        )


def test_url_with_credentials_is_rejected():
    with pytest.raises(ValueError):
        validate_callback_url(
            "https://user:password@example.com/callback",
        )


def test_unresolvable_hostname_is_rejected():
    with patch(
        "app.routes.webhooks.socket.getaddrinfo",
        side_effect=__import__("socket").gaierror,
    ):
        with pytest.raises(ValueError):
            validate_callback_url(
                "https://does-not-exist.invalid/",
            )


def test_webhook_endpoint_never_calls_private_destination(
    client,
    auth_headers,
):
    response = client.post(
        "/v1/webhooks/test",
        headers=auth_headers,
        json={
            "url": "http://127.0.0.1:8001/health",
        },
    )

    assert response.status_code == 400
    assert "private" in response.get_json()["error"].lower()


def test_kyc_rejects_arbitrary_provider_url(
    client,
    auth_headers,
):
    response = client.post(
        "/v1/verify/bvn",
        headers=auth_headers,
        json={
            "bvn": "22134567890",
            "provider": "http://127.0.0.1:8001/health",
        },
    )

    # Only named providers are accepted by the current KYC implementation.
    assert response.status_code == 400