"""Wallet credit and debit operations."""

import uuid

from decimal import Decimal

from flask import (
    Blueprint,
    request,
    jsonify,
)

from app.db import get_connection
from app.auth import require_auth
from app.audit import audit_event


wallets_bp = Blueprint(
    "wallets",
    __name__,
)


@wallets_bp.route(
    "/<int:account_id>/credit",
    methods=["POST"],
)
@require_auth
def credit_wallet(account_id):
    """
    Credit funds into an owned wallet.

    REMEDIATION V-APP-03:
    The target account must belong to the authenticated caller.

    REMEDIATION V-APP-11:
    A structured audit event is emitted after the financial transaction
    successfully commits.
    """
    data = (
        request.get_json()
        or {}
    )

    amount = Decimal(
        str(
            data.get(
                "amount",
                "0",
            )
        )
    )

    description = data.get(
        "description",
        "credit",
    )

    if amount <= 0:
        return jsonify({
            "error": (
                "amount must be positive"
            )
        }), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        # SECURITY:
        # Include the authenticated owner in the account lookup.
        cur.execute(
            """
            SELECT
                balance,
                currency
            FROM accounts
            WHERE id = %s
            AND user_id = %s
            FOR UPDATE
            """,
            (
                account_id,
                request.current_user_id,
            ),
        )
        row = cur.fetchone()

        if not row:
            return jsonify({
                "error": "account not found"
            }), 404

        new_balance = (
            Decimal(
                str(row["balance"])
            )
            + amount
        )

        currency = row[
            "currency"
        ]

        cur.execute(
            """
            UPDATE accounts
            SET balance = %s
            WHERE id = %s
            """,
            (
                new_balance,
                account_id,
            ),
        )

        reference = (
            f"TXN-"
            f"{uuid.uuid4().hex[:12].upper()}"
        )

        cur.execute(
            """
            INSERT INTO transactions (
                account_id,
                reference,
                amount,
                currency,
                direction,
                description,
                status
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                'credit',
                %s,
                'completed'
            )
            """,
            (
                account_id,
                reference,
                amount,
                currency,
                description,
            ),
        )

        conn.commit()

        # AUDIT V-APP-11:
        # Log only after the financial state is committed. The actor, target,
        # amount and transaction reference are retained for investigation.
        audit_event(
            "wallet_credit",
            actor_user_id=(
                request.current_user_id
            ),
            action="wallet_credit",
            target=(
                f"account:{account_id}"
            ),
            account_id=account_id,
            reference=reference,
            amount=str(amount),
            currency=currency,
            ip=request.remote_addr,
        )

        return jsonify({
            "reference": reference,
            "new_balance": str(
                new_balance
            ),
        })

    finally:
        cur.close()
        conn.close()


@wallets_bp.route(
    "/<int:account_id>/debit",
    methods=["POST"],
)
@require_auth
def debit_wallet(account_id):
    """
    Atomically debit funds from an owned wallet.

    REMEDIATION V-APP-03:
    The account owner is enforced in the database query.

    REMEDIATION V-APP-04:
    FOR UPDATE serializes concurrent debits for the same account. The balance
    check and update therefore cannot both operate on the same stale balance.

    REMEDIATION V-APP-11:
    Successful debits produce structured audit records.
    """
    data = (
        request.get_json()
        or {}
    )

    amount = Decimal(
        str(
            data.get(
                "amount",
                "0",
            )
        )
    )

    counterparty = data.get(
        "counterparty",
        "",
    )

    description = data.get(
        "description",
        "debit",
    )

    if amount <= 0:
        return jsonify({
            "error": (
                "amount must be positive"
            )
        }), 400

    conn = get_connection()

    try:
        # FUNCTIONALITY:
        # The context commits all balance/transaction changes as one unit.
        with conn:
            with conn.cursor() as cur:

                # CRITICAL FINANCIAL CONTROL:
                # FOR UPDATE holds the account row until the transaction ends.
                # A second concurrent debit must wait for the first transaction
                # before it is allowed to evaluate the balance.
                cur.execute(
                    """
                    SELECT
                        balance,
                        currency
                    FROM accounts
                    WHERE id = %s
                      AND user_id = %s
                    FOR UPDATE
                    """,
                    (
                        account_id,
                        request.current_user_id,
                    ),
                )

                row = cur.fetchone()

                if not row:
                    return jsonify({
                        "error": (
                            "account not found"
                        )
                    }), 404

                current_balance = Decimal(
                    str(
                        row["balance"]
                    )
                )

                currency = row[
                    "currency"
                ]

                if current_balance < amount:
                    return jsonify({
                        "error": (
                            "insufficient funds"
                        )
                    }), 400

                new_balance = (
                    current_balance
                    - amount
                )

                cur.execute(
                    """
                    UPDATE accounts
                    SET balance = %s
                    WHERE id = %s
                    """,
                    (
                        new_balance,
                        account_id,
                    ),
                )

                reference = (
                    f"TXN-"
                    f"{uuid.uuid4().hex[:12].upper()}"
                )

                cur.execute(
                    """
                    INSERT INTO transactions (
                        account_id,
                        reference,
                        amount,
                        currency,
                        direction,
                        counterparty,
                        description,
                        status
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        'debit',
                        %s,
                        %s,
                        'completed'
                    )
                    """,
                    (
                        account_id,
                        reference,
                        amount,
                        currency,
                        counterparty,
                        description,
                    ),
                )
                
        # AUDIT:
        # This executes only after the transaction context exits successfully.
        audit_event(
            "wallet_debit",
            actor_user_id=(
                request.current_user_id
            ),
            action="wallet_debit",
            target=(
                f"account:{account_id}"
            ),
            account_id=account_id,
            reference=reference,
            amount=str(amount),
            currency=currency,
            counterparty=counterparty,
            ip=request.remote_addr,
        )

        return jsonify({
            "reference": reference,
            "new_balance": str(
                new_balance
            ),
        })

    finally:
        conn.close()