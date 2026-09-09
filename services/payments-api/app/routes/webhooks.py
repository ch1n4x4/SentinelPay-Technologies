"""Webhook registration and callback testing."""
import os
import requests
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

webhooks_bp = Blueprint("webhooks", __name__)

WEBHOOK_TIMEOUT = int(os.environ.get("WEBHOOK_TIMEOUT", "10"))


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
    """Test-fire a webhook by fetching the supplied URL with a sample payload.

    V-APP-04: Server-Side Request Forgery. The URL is fetched with no validation
    of scheme, host, or destination. Try /v1/webhooks/test with
    {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
    once this is deployed to AWS, and the EC2/Fargate instance metadata
    credentials come back in the response body.
    """
    data = request.get_json() or {}
    url = data.get("url")

    if not url:
        return jsonify({"error": "url required"}), 400

    try:
        # No allowlist, no scheme check, no IP filter, no redirect cap.
        resp = requests.get(url, timeout=WEBHOOK_TIMEOUT)
        return jsonify({
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:5000]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
