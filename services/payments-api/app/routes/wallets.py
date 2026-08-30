"""Wallet credit and debit operations."""
import uuid
import json
import logging
from datetime import datetime, timezone
from decimal import Decimal

from flask import Blueprint, request, jsonify

from app.db import get_connection
from app.auth import require_auth

# REMEDIATION START: V-APP-11 Audit Logging
# Removed local audit function and imported the shared module[cite: 27].
from app.audit import audit_event
# REMEDIATION END

wallets_bp = Blueprint("wallets", __name__)


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
        # REMEDIATION START: Fetch currency for audit logging
        cur.execute(
            "SELECT balance, currency FROM accounts WHERE id = %s AND user_id = %s",
            (account_id, request.current_user_id),
        )
        # REMEDIATION END

        row = cur.fetchone()

        if not row:
            return jsonify({"error": "account not found"}), 404

        new_balance = Decimal(str(row["balance"])) + amount
        currency = row["currency"]

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

        # REMEDIATION START: V-APP-11 Credit Audit Logging
        # Emits a structured audit event now that the credit transaction is committed[cite: 34].
        audit_event(
            "wallet_credit",
            actor_user_id=request.current_user_id,
            action="wallet_credit",
            target=f"account:{account_id}",
            account_id=account_id,
            reference=reference,
            amount=str(amount),
            currency=currency,
            ip=request.remote_addr,
        )
        # REMEDIATION END

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
    """Debit funds from a wallet."""
    data = request.get_json() or {}

    amount = Decimal(str(data.get("amount", "0")))
    counterparty = data.get("counterparty", "")
    description = data.get("description", "debit")

    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400

    conn = get_connection()

    try:
        with conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    SELECT balance, currency
                    FROM accounts
                    WHERE id = %s AND user_id = %s
                    FOR UPDATE
                    """,
                    (account_id, request.current_user_id),
                )

                row = cur.fetchone()

                if not row:
                    return jsonify({"error": "account not found"}), 404

                current_balance = Decimal(str(row["balance"]))
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