"""Transaction search and listing endpoints."""
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

transactions_bp = Blueprint("transactions", __name__)


@transactions_bp.route("/search", methods=["GET"])
@require_auth
def search_transactions():
    """Search transactions by reference, counterparty, or description.

    V-APP-01 Fixed: SQL Injection eliminated by using parameterized queries 
    instead of f-string concatenation.
    """
    # REMEDIATION START: Safely extract parameters without direct SQL injection risk
    q = request.args.get("q", "")
    account_id = request.args.get("account_id")
    # REMEDIATION END

    conn = get_connection()
    cur = conn.cursor()
    try:
        # REMEDIATION START: V-APP-01 Parameterised Query Implementation
        # Replaced vulnerable f-strings with %s placeholders. This ensures the database 
        # driver safely escapes the payload, treating it as a literal string rather than SQL.
        sql = """
            SELECT id, account_id, reference, amount, currency, direction,
                   counterparty, description, status, created_at
            FROM transactions
            WHERE (
                reference LIKE %s
                OR counterparty LIKE %s
                OR description LIKE %s
            )
        """
        params = [f"%{q}%", f"%{q}%", f"%{q}%"]

        if account_id:
            # Typecasting validates the input, immediately rejecting malicious strings
            try:
                account_id = int(account_id)
            except (TypeError, ValueError):
                return jsonify({"error": "invalid account_id"}), 400

            sql += " AND account_id = %s"
            params.append(account_id)

        sql += " ORDER BY created_at DESC LIMIT 50"

        cur.execute(sql, params)
        # REMEDIATION END

        rows = cur.fetchall()
        results = []
        for r in rows:
            row_dict = dict(r)
            if 'amount' in row_dict and row_dict['amount'] is not None:
                row_dict['amount'] = str(row_dict['amount'])
            results.append(row_dict)

        return jsonify(results)
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
        # REMEDIATION START: V-APP-03 Transaction Ownership Check
        # Constrain the transaction lookup to ensure the associated account
        # belongs to the currently authenticated user[cite: 12].
        cur.execute(
            """
            SELECT *
            FROM transactions
            WHERE reference = %s
              AND account_id IN (
                  SELECT id
                  FROM accounts
                  WHERE user_id = %s
              )
            """,
            (reference, request.current_user_id)
        )
        # REMEDIATION END
        
        txn = cur.fetchone()
        if not txn:
            return jsonify({"error": "transaction not found"}), 404
            
        txn_dict = dict(txn)
        if 'amount' in txn_dict and txn_dict['amount'] is not None:
            txn_dict['amount'] = str(txn_dict['amount'])
            
        return jsonify(txn_dict)
    finally:
        cur.close()
        conn.close()