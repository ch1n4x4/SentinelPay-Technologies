"""Transaction search and listing endpoints."""
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

transactions_bp = Blueprint("transactions", __name__)


@transactions_bp.route("/search", methods=["GET"])
@require_auth
def search_transactions():
    """Search transactions by reference, counterparty, or description.

    V-APP-01: Classic SQL injection. The `q` parameter is concatenated directly
    into the WHERE clause. Try /v1/transactions/search?q=' OR '1'='1
    """
    q = request.args.get("q", "")
    account_id = request.args.get("account_id", "")

    conn = get_connection()
    cur = conn.cursor()
    try:
        # Concatenation, not parameterisation. Bypass auth scoping with a clever payload.
        query = (
            "SELECT id, account_id, reference, amount, currency, direction, "
            "counterparty, description, status, created_at "
            f"FROM transactions WHERE (reference LIKE '%{q}%' "
            f"OR counterparty LIKE '%{q}%' OR description LIKE '%{q}%')"
        )
        if account_id:
            query += f" AND account_id = {account_id}"
        query += " ORDER BY created_at DESC LIMIT 50"

        cur.execute(query)
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        cur.close()
        conn.close()


@transactions_bp.route("/<reference>", methods=["GET"])
@require_auth
def get_transaction(reference):
    """Fetch a single transaction by reference."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT * FROM transactions WHERE reference = %s",
            (reference,)
        )
        txn = cur.fetchone()
        if not txn:
            return jsonify({"error": "transaction not found"}), 404
        return jsonify(dict(txn))
    finally:
        cur.close()
        conn.close()
