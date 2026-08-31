def test_concurrent_debits_leave_correct_balance(
    authenticated_client_factory,
    get_account_balance,
):
    starting_balance = get_account_balance(3)

    amount = "180.00"

    def debit():
        client = authenticated_client_factory()
        return client.post(
            "/v1/wallets/3/debit",
            json={
                "amount": amount,
                "description": "concurrency regression",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(
            executor.map(lambda _: debit(), range(2))
        )

    assert sorted(
        response.status_code for response in responses
    ) == [200, 400]

    final_balance = get_account_balance(3)

    assert final_balance == starting_balance - 180