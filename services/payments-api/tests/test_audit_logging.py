"""Audit logging regression tests."""

import json
import logging


def test_wallet_debit_emits_audit_event(
    client,
    auth_headers,
    caplog,
):
    caplog.set_level(
        logging.INFO,
        logger="sentinelpay.audit",
    )

    response = client.post(
        "/v1/wallets/3/debit",
        headers=auth_headers,
        json={
            "amount": "1.00",
            "description": "audit-test",
        },
    )

    assert response.status_code == 200

    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "sentinelpay.audit"
    ]

    event = next(
        event
        for event in events
        if event["event"] == "wallet_debit"
    )

    assert "actor_user_id" in event
    assert "account_id" in event
    assert "reference" in event
    assert "amount" in event
    assert "timestamp" in event


def test_wallet_credit_emits_audit_event(
    client,
    auth_headers,
    caplog,
):
    caplog.set_level(
        logging.INFO,
        logger="sentinelpay.audit",
    )

    response = client.post(
        "/v1/wallets/3/credit",
        headers=auth_headers,
        json={
            "amount": "1.00",
            "description": "audit-test",
        },
    )

    assert response.status_code == 200

    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "sentinelpay.audit"
    ]

    assert any(
        event["event"] == "wallet_credit"
        for event in events
    )


def test_kyc_status_change_emits_audit_event(
    kyc_client,
    admin_auth_headers,
    caplog,
):
    caplog.set_level(
        logging.INFO,
        logger="sentinelpay.audit",
    )

    response = kyc_client.put(
        "/v1/verify/1/status",
        headers=admin_auth_headers,
        json={"status": "verified"},
    )

    assert response.status_code == 200

    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "sentinelpay.audit"
    ]

    assert any(
        event["event"] == "kyc_status_change"
        for event in events
    )


def test_audit_logging_redacts_sensitive_values(caplog):
    from app.audit import audit_event

    caplog.set_level(
        logging.INFO,
        logger="sentinelpay.audit",
    )

    audit_event(
        "security-test",
        token="secret-token",
        password="secret-password",
        otp="123456",
        session="sensitive-session",
    )

    message = caplog.records[-1].message

    assert "secret-token" not in message
    assert "secret-password" not in message
    assert "123456" not in message
    assert "sensitive-session" not in message
    assert "***" in message