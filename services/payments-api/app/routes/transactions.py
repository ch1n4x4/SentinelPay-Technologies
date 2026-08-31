"""Transaction search and listing endpoints."""

from flask import (
    Blueprint,
    request,
    jsonify,
)

from app.db import get_connection
from app.auth import require_auth


transactions_bp = Blueprint(
    "transactions",
    __name__,
)


@transactions_bp.route(
    "/search",
    methods=["GET"],
)
@require_auth
def search_transactions():
    """
    Search transaction records.

    REMEDIATION V-APP-01:
    main constructed the WHERE clause with f-strings. All request data is now
    represented by PostgreSQL parameters.
    """
    q = request.args.get(
        "q",
        "",
    )

    account_id = request.args.get(
        "account_id"
    )

    conn = get_connection()
    cur = conn.cursor()

    try:
        # SECURITY:
        # The search term is treated as data, never SQL syntax.
        sql = """
            SELECT
                id,
                account_id,
                reference,
                amount,
                currency,
                direction,
                counterparty,
                description,
                status,
                created_at
            FROM transactions
            WHERE (
                reference LIKE %s
                OR counterparty LIKE %s
                OR description LIKE %s
            )
        """

        params = [
            f"%{q}%",
            f"%{q}%",
            f"%{q}%",
        ]

        if account_id:
            # SECURITY:
            # account_id has an expected integer type. Reject anything else
            # rather than passing SQL syntax through to PostgreSQL.
            try:
                account_id = int(
                    account_id
                )
            except (
                TypeError,
                ValueError,
            ):
                return jsonify({
                    "error": (
                        "invalid account_id"
                    )
                }), 400

            sql += (
                " AND account_id = %s"
            )

            params.append(
                account_id
            )

        sql += """
            ORDER BY created_at DESC
            LIMIT 50
        """

        cur.execute(
            sql,
            params,
        )

        rows = cur.fetchall()
        results = []

        for row in rows:
            row_dict = dict(
                row
            )

            if (
                "amount" in row_dict
                and row_dict["amount"]
                is not None
            ):
                row_dict[
                    "amount"
                ] = str(
                    row_dict["amount"]
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


@transactions_bp.route(
    "/<reference>",
    methods=["GET"],
)
@require_auth
def get_transaction(
    reference,
):
    """
    Fetch a transaction owned by the caller.

    REMEDIATION V-APP-03:
    A transaction reference alone does not authorize access. The query must
    establish that the associated account belongs to the authenticated user.
    """
    conn = get_connection()
    cur = conn.cursor()

    try:
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
            (
                reference,
                request.current_user_id,
            ),
        )

        txn = cur.fetchone()

        if not txn:
            return jsonify({
                "error": (
                    "transaction not found"
                )
            }), 404

        txn_dict = dict(
            txn
        )

        if (
            "amount" in txn_dict
            and txn_dict["amount"]
            is not None
        ):
            txn_dict[
                "amount"
            ] = str(
                txn_dict["amount"]
            )

        return jsonify(
            txn_dict
        )

    finally:
        cur.close()
        conn.close()