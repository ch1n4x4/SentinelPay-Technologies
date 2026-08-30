"""Account lookup and listing endpoints."""
from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

accounts_bp = Blueprint("accounts", __name__)


@accounts_bp.route("/<int:account_id>", methods=["GET"])
@require_auth
def get_account(account_id):
    """Look up an account by ID.

    V-APP-03(IDOR) Fixed:
    Scope the lookup to the authenticated principal
    Do not rely on merely hiding account IDs; authorization must occur server-side.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, user_id, account_number, currency, balance, status, created_at
            FROM accounts
            WHERE id = %s AND user_id = %s
            """,
            (account_id, request.current_user_id),
        )

        account = cur.fetchone()

        if not account:
            return jsonify({"error": "account not found"}), 404
        account_dict = dict(account)
        if 'balance' in account_dict and account_dict['balance'] is not None:
            account_dict['balance'] = str(account_dict['balance'])
        return jsonify(account_dict)
    finally:
        cur.close()
        conn.close()


@accounts_bp.route("/", methods=["GET"])
@require_auth
def list_accounts():
    """List accounts belonging to the current user."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, account_number, currency, balance, status FROM accounts WHERE user_id = %s",
            (request.current_user_id,)
        )
        rows = cur.fetchall()
        results = []
        for r in rows:
            row_dict = dict(r)
            if 'balance' in row_dict and row_dict['balance'] is not None:
                row_dict['balance'] = str(row_dict['balance'])
            results.append(row_dict)
        return jsonify(results)
    finally:
        cur.close()
        conn.close()


@accounts_bp.route("/<int:account_id>/profile", methods=["PUT"])
@require_auth
def update_profile(account_id):
    """Update account profile fields.

    V-APP-07: Mass assignment. The update accepts an arbitrary dict and writes
    every key the client provides, including 'status', 'user_id', and 'balance'.
    A merchant can transfer an account to themselves or set their balance.
    """
    data = request.get_json() or {}
    conn = get_connection()
    cur = conn.cursor()
    try:
        # Build dynamic SET clause from whatever the client sent
        if not data:
            return jsonify({"error": "no fields supplied"}), 400

        set_clause = ", ".join([f"{k} = %s" for k in data.keys()])
        values = list(data.values()) + [account_id]
        # Note: this is intentionally a parameterised query for the *values*,
        # but the column names are concatenated from user input — see V-APP-07.
        # SQLi on column names is not the bug here; mass assignment is.
        cur.execute(f"UPDATE accounts SET {set_clause} WHERE id = %s RETURNING *", values)
        updated = cur.fetchone()
        conn.commit()
        # Convert Decimal to string so Flask can serialize it
        updated_dict = dict(updated)
        if 'balance' in updated_dict and updated_dict['balance'] is not None:
            updated_dict['balance'] = str(updated_dict['balance'])
            
        return jsonify(updated_dict)
    finally:
        cur.close()
        conn.close()
