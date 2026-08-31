"""SSRF regression tests."""

import pytest

from app.routes.webhooks import validate_callback_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
    ],
)
def test_private_or_local_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_callback_url(url)


def test_http_scheme_is_rejected():
    with pytest.raises(ValueError):
        validate_callback_url("http://example.com/")


def test_userinfo_is_rejected():
    with pytest.raises(ValueError):
        validate_callback_url(
            "https://user:password@example.com/"
        )


def test_unknown_provider_is_rejected(kyc_client, auth_headers):
    response = kyc_client.post(
        "/v1/verify/bvn",
        headers=auth_headers,
        json={
            "bvn": "22134567890",
            "provider": "http://127.0.0.1:8001/health",
        },
    )

    assert response.status_code == 400