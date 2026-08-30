"""Webhook registration and callback testing."""
import os
import requests
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth
from urllib.parse import urlparse
import ipaddress
import socket

WEBHOOK_TIMEOUT = int(os.environ.get("WEBHOOK_TIMEOUT", "10"))

"""
Added allowlist of registered HTTPS callback destinations validator
"""
def validate_callback_url(url: str) -> None:
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError("callback must use HTTPS")

    if parsed.username or parsed.password:
        raise ValueError("userinfo not allowed in URL")

    if not parsed.hostname:
        raise ValueError("hostname required")

    try:
        addresses = socket.getaddrinfo(
            parsed.hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        raise ValueError("hostname could not be resolved")

    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise ValueError(
                "private/reserved destination is not allowed"
            )
        
webhooks_bp = Blueprint("webhooks", __name__)


@webhooks_bp.route("/", methods=["POST"])
@require_auth
def register_webhook():
    """Register a callback URL for transaction events."""
    data = request.get_json() or {}
    callback_url = data.get("callback_url")
    event_type = data.get("event_type", "transaction.completed")

    if not callback_url:
        return jsonify({"error": "callback_url required"}), 400

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO webhooks (user_id, callback_url, event_type) VALUES (%s, %s, %s) RETURNING id",
            (request.current_user_id, callback_url, event_type)
        )
        webhook_id = cur.fetchone()["id"]
        conn.commit()
        return jsonify({"id": webhook_id, "callback_url": callback_url}), 201
    finally:
        cur.close()
        conn.close()


@webhooks_bp.route("/test", methods=["POST"])
@require_auth
def test_webhook():
    """
    V-APP-04 (SSRF) Fixed: call validate_callback_url() on the callback URL 
    immediately before the HTTP client is invoked.
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url:
        return jsonify({"error": "url required"}), 400

    try:
        validate_callback_url(url)

        resp = requests.get(
            url,
            timeout=WEBHOOK_TIMEOUT,
            allow_redirects=False,
        )

        return jsonify({
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:5000],
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    except requests.RequestException:
        return jsonify({"error": "callback request failed"}), 502
