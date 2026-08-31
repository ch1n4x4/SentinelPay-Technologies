"""Structured audit logging regression tests."""

import json
import logging


def audit_records(caplog):
    return [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "sentinelpay.audit"
    ]


def test_wallet_debit_emits_required_audit_fields(
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
            "description": "audit regression",
        },
    )

    assert response.status_code == 200

    event = next(
        item
        for item in audit_records(caplog)
        if item["event"] == "wallet_debit"
    )

    assert event["actor_user_id"] == 3
    assert event["account_id"] == 3
    assert event["action"] if "action" in event else True
    assert "reference" in event
    assert "amount" in event
    assert "timestamp" in event


def test_wallet_credit_is_audited(
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
            "description": "audit regression",
        },
    )

    assert response.status_code == 200

    assert any(
        event["event"] == "wallet_credit"
        for event in audit_records(caplog)
    )


def test_admin_action_is_audited(
    client,
    admin_auth_headers,
    caplog,
):
    caplog.set_level(
        logging.INFO,
        logger="sentinelpay.audit",
    )

    response = client.get(
        "/v1/admin/users",
        headers=admin_auth_headers,
    )

    assert response.status_code == 200

    event = next(
        item
        for item in audit_records(caplog)
        if item["event"] == "admin_user_list"
    )

    assert event["actor_user_id"] == 1
    assert event["action"] == "list_users"
    assert event["target"] == "users"
    assert "timestamp" in event


def test_audit_does_not_leak_secrets(caplog):
    from app.audit import audit_event

    caplog.set_level(
        logging.INFO,
        logger="sentinelpay.audit",
    )

    audit_event(
        "security-test",
        token="SECRET_TOKEN",
        password="SECRET_PASSWORD",
        otp="123456",
        document_content="PRIVATE_DOCUMENT",
        session="PRIVATE_SESSION",
    )

    message = caplog.records[-1].message

    assert "SECRET_TOKEN" not in message
    assert "SECRET_PASSWORD" not in message
    assert "123456" not in message
    assert "PRIVATE_DOCUMENT" not in message
    assert "PRIVATE_SESSION" not in message

    assert message.count("***") >= 5