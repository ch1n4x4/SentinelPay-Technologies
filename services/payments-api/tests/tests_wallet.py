from concurrent.futures import ThreadPoolExecutor


def test_concurrent_debits_do_not_overspend(authenticated_client_factory):
    def debit():
        client = authenticated_client_factory()
        return client.post(
            "/v1/wallets/3/debit",
            json={
                "amount": "180.00",
                "description": "concurrency regression",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: debit(), range(2)))

    statuses = sorted(response.status_code for response in responses)

    assert statuses == [200, 400]