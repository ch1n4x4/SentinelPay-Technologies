"""Shared fixtures for payments-api security regression tests."""

import os
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.main import create_app


@pytest.fixture(scope="session")
def key_pair():
    """Generate an isolated RSA key pair for the test process."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


@pytest.fixture
def private_key(key_pair):
    return key_pair[0]


@pytest.fixture
def rsa_public_key(key_pair):
    return key_pair[1]


@pytest.fixture(autouse=True)
def security_environment(monkeypatch, key_pair):
    """Configure the application to use test-only security material."""
    private_key, public_key = key_pair

    monkeypatch.setenv(
        "JWT_PRIVATE_KEY",
        private_key.decode("utf-8"),
    )
    monkeypatch.setenv(
        "JWT_PUBLIC_KEY",
        public_key.decode("utf-8"),
    )
    monkeypatch.setenv(
        "SESSION_SIGNING_KEY",
        "unit-test-session-signing-key",
    )

    # Flask-Limiter's in-memory backend keeps tests isolated.
    monkeypatch.setenv(
        "RATELIMIT_STORAGE_URI",
        "memory://",
    )


@pytest.fixture
def app():
    application = create_app()
    application.config.update(
        TESTING=True,
    )
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def make_token(private_key, user_id, role="merchant", **extra):
    now = datetime.now(timezone.utc)

    payload = {
        "user_id": user_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "typ": "access",
    }

    payload.update(extra)

    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )


@pytest.fixture
def user_1_header(private_key):
    token = make_token(
        private_key,
        user_id=3,
        role="merchant",
    )

    return {
        "Authorization": f"Bearer {token}",
    }


@pytest.fixture
def user_2_header(private_key):
    token = make_token(
        private_key,
        user_id=4,
        role="merchant",
    )

    return {
        "Authorization": f"Bearer {token}",
    }


@pytest.fixture
def admin_auth_headers(private_key):
    token = make_token(
        private_key,
        user_id=1,
        role="admin",
    )

    return {
        "Authorization": f"Bearer {token}",
    }


@pytest.fixture
def auth_headers(user_1_header):
    return user_1_header


@pytest.fixture
def user_2_account_id():
    return 5


@pytest.fixture
def user_2_transaction_id():
    return "TXN-2026-004"


@pytest.fixture
def client_factory(app):
    def factory(remote_addr="127.0.0.1"):
        test_client = app.test_client()
        test_client.environ_base["REMOTE_ADDR"] = remote_addr
        return test_client

    return factory