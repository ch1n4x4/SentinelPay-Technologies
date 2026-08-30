"""Wallet credit and debit operations."""
import uuid
import json
import logging
from datetime import datetime, timezone
from decimal import Decimal

from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

wallets_bp = Blueprint("wallets", __name__)


# ============================================================
# REMEDIATION BLOCK: V-APP-11 - Structured audit logging
#
# Add a dedicated audit logger so sensitive money-movement
# operations are recorded with structured, machine-readable
# fields.
# ============================================================
audit_logger = logging.getLogger("sentinelpay.audit")


def audit_event(event: str, **fields):
    """Write a structured audit event to the application logger."""
    audit_logger.info(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **fields,
            },
            separators=(",", ":"),
        )
    )


@wallets_bp.route("/<int:account_id>/credit", methods=["POST"])
@require_auth
def credit_wallet(account_id):
    """Credit funds to a wallet (e.g. inbound transfer settlement)."""
    data = request.get_json() or {}
    amount = Decimal(str(data.get("amount", "0")))
    description = data.get("description", "credit")

    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT balance FROM accounts WHERE id = %s",
            (account_id,),
        )

        row = cur.fetchone()

        if not row:
            return jsonify({"error": "account not found"}), 404

        new_balance = Decimal(str(row["balance"])) + amount

        cur.execute(
            "UPDATE accounts SET balance = %s WHERE id = %s",
            (new_balance, account_id),
        )

        reference = f"TXN-{uuid.uuid4().hex[:12].upper()}"

        cur.execute(
            "INSERT INTO transactions "
            "(account_id, reference, amount, direction, description, status) "
            "VALUES (%s, %s, %s, 'credit', %s, 'completed')",
            (
                account_id,
                reference,
                amount,
                description,
            ),
        )

        conn.commit()

        return jsonify(
            {
                "reference": reference,
                "new_balance": str(new_balance),
            }
        )

    finally:
        cur.close()
        conn.close()


@wallets_bp.route("/<int:account_id>/debit", methods=["POST"])
@require_auth
def debit_wallet(account_id):
    """Debit funds from a wallet.

    V-APP-05: Race-condition remediation.
    The account row is locked using SELECT ... FOR UPDATE and the
    balance check, balance update, and transaction insert occur
    within the same database transaction.

    V-APP-11: Missing audit-log remediation.
    A structured audit event is emitted after the database
    transaction successfully commits.
    """
    data = request.get_json() or {}

    amount = Decimal(str(data.get("amount", "0")))
    counterparty = data.get("counterparty", "")
    description = data.get("description", "debit")

    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400

    conn = get_connection()

    try:
        # ========================================================
        # REMEDIATION BLOCK: V-APP-05 - Atomic transaction +
        # row-level locking
        #
        # FOR UPDATE locks this account row until the transaction
        # commits or rolls back. This prevents concurrent debit
        # requests from reading the same balance simultaneously.
        #
        # The account balance, currency, validation, update, and
        # transaction insertion all happen within the same DB
        # transaction.
        # ========================================================
        with conn:
            with conn.cursor() as cur:

                # Retrieve and lock the account row.
                #
                # IMPORTANT:
                # The currency is read from the account rather than
                # hard-coded so the application can support NGN,
                # USD, EUR, GBP, or other supported currencies.
                cur.execute(
                    """
                    SELECT balance, currency
                    FROM accounts
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (account_id,),
                )

                row = cur.fetchone()

                if not row:
                    return jsonify({"error": "account not found"}), 404

                current_balance = Decimal(str(row["balance"]))

                # ====================================================
                # REMEDIATION BLOCK: V-APP-11 - Dynamic currency
                #
                # Use the currency stored on the account for the
                # audit event instead of assuming NGN.
                # ====================================================
                currency = row["currency"]

                if current_balance < amount:
                    return jsonify({"error": "insufficient funds"}), 400

                new_balance = current_balance - amount

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

                reference = f"TXN-{uuid.uuid4().hex[:12].upper()}"

                cur.execute(
                    """
                    INSERT INTO transactions
                        (
                            account_id,
                            reference,
                            amount,
                            direction,
                            counterparty,
                            description,
                            status
                        )
                    VALUES
                        (%s, %s, %s, 'debit', %s, %s, 'completed')
                    """,
                    (
                        account_id,
                        reference,
                        amount,
                        counterparty,
                        description,
                    ),
                )

        # ========================================================
        # REMEDIATION BLOCK: V-APP-11 - Audit logging
        #
        # This is intentionally outside the transaction block.
        # The audit event is therefore emitted only after the
        # database transaction has committed successfully.
        #
        # Currency comes from the actual account record rather
        # than being hard-coded to NGN.
        # ========================================================
        audit_event(
            "wallet_debit",
            actor_user_id=request.current_user_id,
            account_id=account_id,
            reference=reference,
            amount=str(amount),
            currency=currency,
            counterparty=counterparty,
            ip=request.remote_addr,
        )

        return jsonify(
            {
                "reference": reference,
                "new_balance": str(new_balance),
            }
        )

    finally:
        conn.close()