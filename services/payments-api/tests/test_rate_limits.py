"""Rate-limiting regression tests."""

import pytest


def test_login_is_rate_limited_by_ip(client):
    statuses = []

    for _ in range(7):
        response = client.post(
            "/v1/auth/login",
            json={
                "email": "user1@example.com",
                "password": "wrong",
            },
        )
        statuses.append(response.status_code)

    assert 429 in statuses


def test_login_is_rate_limited_by_account(
    client_factory,
    monkeypatch,
):
    clients = [
        client_factory(remote_addr=f"10.0.0.{i}")
        for i in range(1, 7)
    ]

    statuses = []

    for client in clients:
        response = client.post(
            "/v1/auth/login",
            json={
                "email": "same-target@example.com",
                "password": "wrong",
            },
        )
        statuses.append(response.status_code)

    assert 429 in statuses


def test_otp_is_rate_limited_by_phone(client_factory):
    clients = [
        client_factory(remote_addr=f"10.0.1.{i}")
        for i in range(1, 7)
    ]

    statuses = []

    for client in clients:
        response = client.post(
            "/v1/auth/otp",
            json={
                "phone": "+2348000000000",
            },
        )
        statuses.append(response.status_code)

    assert 429 in statuses