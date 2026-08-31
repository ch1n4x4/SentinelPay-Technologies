"""Webhook registration and callback testing."""

import ipaddress
import os
import socket

from urllib.parse import urlparse

import requests

from flask import (
    Blueprint,
    request,
    jsonify,
)

from app.db import get_connection
from app.auth import require_auth


WEBHOOK_TIMEOUT = int(
    os.environ.get(
        "WEBHOOK_TIMEOUT",
        "10",
    )
)


# ============================================================================
# V-APP-05: OUTBOUND URL VALIDATION
# ============================================================================
#
# REMEDIATION:
# Prevent server-side requests from reaching internal/private network
# destinations. The validator is also used at registration so unsafe callback
# URLs do not become persisted trusted configuration.
def validate_callback_url(
    url: str,
) -> None:
    parsed = urlparse(
        url
    )

    if parsed.scheme != "https":
        raise ValueError(
            "callback must use HTTPS"
        )

    if (
        parsed.username
        or parsed.password
    ):
        raise ValueError(
            "userinfo not allowed in URL"
        )

    if not parsed.hostname:
        raise ValueError(
            "hostname required"
        )

    try:
        addresses = socket.getaddrinfo(
            parsed.hostname,
            443,
            type=socket.SOCK_STREAM,
        )

    except socket.gaierror:
        raise ValueError(
            "hostname could not be resolved"
        )

    for item in addresses:
        ip = ipaddress.ip_address(
            item[4][0]
        )

        # SECURITY:
        # Block loopback/private/link-local/reserved/multicast destinations.
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise ValueError(
                "private/reserved destination "
                "is not allowed"
            )


webhooks_bp = Blueprint(
    "webhooks",
    __name__,
)


@webhooks_bp.route(
    "/",
    methods=["POST"],
)
@require_auth
def register_webhook():
    """
    Store an outbound transaction callback.

    SECURITY:
    Validate before persisting so a future callback dispatcher cannot inherit
    an unvalidated attacker-controlled URL.
    """
    data = (
        request.get_json()
        or {}
    )

    callback_url = data.get(
        "callback_url"
    )

    event_type = data.get(
        "event_type",
        "transaction.completed",
    )

    if not callback_url:
        return jsonify({
            "error": (
                "callback_url required"
            )
        }), 400

    try:
        validate_callback_url(
            callback_url
        )

    except ValueError as exc:
        return jsonify({
            "error": str(exc)
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            INSERT INTO webhooks (
                user_id,
                callback_url,
                event_type
            )
            VALUES (
                %s,
                %s,
                %s
            )
            RETURNING id
            """,
            (
                request.current_user_id,
                callback_url,
                event_type,
            ),
        )

        webhook_id = cur.fetchone()[
            "id"
        ]

        conn.commit()

        return jsonify({
            "id": webhook_id,
            "callback_url": callback_url,
        }), 201

    finally:
        cur.close()
        conn.close()


@webhooks_bp.route(
    "/test",
    methods=["POST"],
)
@require_auth
def test_webhook():
    """
    Test a callback endpoint.

    REMEDIATION V-APP-05:
    Validate immediately before the outbound HTTP call. Redirects are disabled
    so a public URL cannot redirect the server into an internal destination.
    """
    data = (
        request.get_json()
        or {}
    )

    url = data.get(
        "url"
    )

    if not url:
        return jsonify({
            "error": "url required"
        }), 400

    try:
        validate_callback_url(
            url
        )

        response = requests.get(
            url,
            timeout=WEBHOOK_TIMEOUT,
            allow_redirects=False,
        )

        return jsonify({
            "status_code": (
                response.status_code
            ),
            "headers": dict(
                response.headers
            ),
            "body": response.text[:5000],
        })

    except ValueError as exc:
        return jsonify({
            "error": str(exc)
        }), 400

    except requests.RequestException:
        # SECURITY:
        # Do not expose HTTP client exception details to the caller.
        return jsonify({
            "error": (
                "callback request failed"
            )
        }), 502