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

    V-APP-07(Mass Assignment) Fixed:
    Enforce a strict allowlist of modifiable fields and reject requests containing
    unauthorized keys. Combined with V-APP-03 IDOR fix in the SQL statement.
    """
    # REMEDIATION START: V-APP-07 Strict field allowlisting
    ALLOWED_FIELDS = {
        "account_number",
        "currency",
    }

    data = request.get_json() or {}

    unknown = set(data) - ALLOWED_FIELDS
    if unknown:
        return jsonify({
            "error": "unsupported fields",
            "fields": sorted(unknown),
        }), 400

    if not data:
        return jsonify({"error": "no fields supplied"}), 400
    # REMEDIATION END

    conn = get_connection()
    cur = conn.cursor()
    try:
        # REMEDIATION START: Safely parameterizing only allowed fields
        set_clause = ", ".join(f"{field} = %s" for field in data)
        values = [data[field] for field in data]

        values.append(account_id)

        # REMEDIATION START: V-APP-03 Enforcing ownership constraint during UPDATE
        cur.execute(
            f"""
            UPDATE accounts
            SET {set_clause}
            WHERE id = %s
              AND user_id = %s
            RETURNING *
            """,
            values + [request.current_user_id],
        )
        # REMEDIATION END

        updated = cur.fetchone()
        
        # Handle cases where the IDOR constraint prevents the update
        if not updated:
            return jsonify({"error": "account not found or update unauthorized"}), 404
            
        conn.commit()
        
        # Convert Decimal to string so Flask can serialize it
        updated_dict = dict(updated)
        if 'balance' in updated_dict and updated_dict['balance'] is not None:
            updated_dict['balance'] = str(updated_dict['balance'])
            
        return jsonify(updated_dict)
    finally:
        cur.close()
        conn.close()