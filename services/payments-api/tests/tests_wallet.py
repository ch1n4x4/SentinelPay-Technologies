"""Wallet concurrency regression tests."""

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal


def test_concurrent_debits_do_not_overspend(
    authenticated_client_factory,
    get_account_balance,
):
    account_id = 3
    debit_amount = Decimal("180.00")

    starting_balance = get_account_balance(
        account_id,
    )

    def debit():
        client = authenticated_client_factory()

        return client.post(
            f"/v1/wallets/{account_id}/debit",
            json={
                "amount": str(debit_amount),
                "description": "concurrency regression",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(
            executor.map(
                lambda _: debit(),
                range(2),
            )
        )

    assert sorted(
        response.status_code
        for response in responses
    ) == [200, 400]

    final_balance = get_account_balance(
        account_id,
    )

    assert final_balance == (
        starting_balance - debit_amount
    )