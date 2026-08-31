"""Account lookup and listing endpoints."""

from flask import (
    Blueprint,
    jsonify,
    request,
)

from app.auth import require_auth
from app.db import get_connection


accounts_bp = Blueprint(
    "accounts",
    __name__,
)


@accounts_bp.route(
    "/<int:account_id>",
    methods=["GET"],
)
@require_auth
def get_account(account_id):
    """
    Return an account owned by the caller.

    REMEDIATION V-APP-03:
    The authenticated user ID is part of the database predicate. Knowing an
    account ID is therefore not sufficient to read another customer's account.
    """
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT
                id,
                user_id,
                account_number,
                currency,
                balance,
                status,
                created_at
            FROM accounts
            WHERE id = %s
              AND user_id = %s
            """,
            (
                account_id,
                request.current_user_id,
            ),
        )

        account = cur.fetchone()

        if not account:
            # SECURITY:
            # Return a generic not-found result instead of confirming that an
            # object belonging to another user exists.
            return jsonify({
                "error": "account not found"
            }), 404

        account_dict = dict(
            account
        )

        if (
            "balance" in account_dict
            and account_dict["balance"]
            is not None
        ):
            account_dict[
                "balance"
            ] = str(
                account_dict["balance"]
            )

        return jsonify(
            account_dict
        )

    finally:
        cur.close()
        conn.close()


@accounts_bp.route(
    "/",
    methods=["GET"],
)
@require_auth
def list_accounts():
    """
    List only the accounts owned by the authenticated user.

    FUNCTIONALITY:
    Returns account balances and metadata for the caller's own accounts.
    """
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT
                id,
                account_number,
                currency,
                balance,
                status
            FROM accounts
            WHERE user_id = %s
            """,
            (
                request.current_user_id,
            ),
        )

        rows = cur.fetchall()
        results = []

        for row in rows:
            row_dict = dict(
                row
            )

            if (
                "balance" in row_dict
                and row_dict["balance"]
                is not None
            ):
                row_dict[
                    "balance"
                ] = str(
                    row_dict["balance"]
                )

            results.append(
                row_dict
            )

        return jsonify(
            results
        )

    finally:
        cur.close()
        conn.close()


@accounts_bp.route(
    "/<int:account_id>/profile",
    methods=["PUT"],
)
@require_auth
def update_profile(account_id):
    """
    Update permitted account profile fields.

    REMEDIATION V-APP-07:
    Client-supplied fields are strictly allowlisted.

    REMEDIATION V-APP-03:
    The target account must belong to the authenticated user.

    REMEDIATION V-APP-01:
    Actual values are SQL parameters rather than interpolated SQL.
    """
    allowed_fields = {
        "account_number",
        "currency",
    }

    data = request.get_json(
        silent=True
    ) or {}

    if not isinstance(
        data,
        dict,
    ):
        return jsonify({
            "error": "invalid JSON object"
        }), 400

    unknown_fields = (
        set(data)
        - allowed_fields
    )

    if unknown_fields:
        return jsonify({
            "error": "unsupported fields",
            "fields": sorted(
                unknown_fields
            ),
        }), 400

    if not data:
        return jsonify({
            "error": "no fields supplied"
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        # SECURITY:
        # Use one fixed SQL statement. No request-controlled field name is
        # inserted into the SQL text.
        cur.execute(
            """
            UPDATE accounts
            SET
                account_number = CASE
                    WHEN %s THEN %s
                    ELSE account_number
                END,
                currency = CASE
                    WHEN %s THEN %s
                    ELSE currency
                END
            WHERE id = %s
              AND user_id = %s
            RETURNING
                id,
                user_id,
                account_number,
                currency,
                balance,
                status,
                created_at
            """,
            (
                "account_number" in data,
                data.get(
                    "account_number"
                ),
                "currency" in data,
                data.get(
                    "currency"
                ),
                account_id,
                request.current_user_id,
            ),
        )

        updated = cur.fetchone()

        if not updated:
            conn.rollback()

            return jsonify({
                "error": (
                    "account not found or "
                    "update unauthorized"
                )
            }), 404

        conn.commit()

        updated_dict = dict(
            updated
        )

        if (
            "balance" in updated_dict
            and updated_dict["balance"]
            is not None
        ):
            updated_dict[
                "balance"
            ] = str(
                updated_dict["balance"]
            )

        return jsonify(
            updated_dict
        )

    except Exception:
        conn.rollback()
        raise

    finally:
        cur.close()
        conn.close()