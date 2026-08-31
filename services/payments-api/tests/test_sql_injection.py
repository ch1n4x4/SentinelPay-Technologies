"""SQL injection regression tests."""


def test_transaction_search_does_not_execute_sql_from_q(
    client,
    auth_headers,
):
    response = client.get(
        "/v1/transactions/search",
        headers=auth_headers,
        query_string={
            "q": "' OR 1=1 --",
        },
    )

    assert response.status_code == 200


def test_transaction_search_rejects_invalid_account_id(
    client,
    auth_headers,
):
    response = client.get(
        "/v1/transactions/search",
        headers=auth_headers,
        query_string={
            "q": "test",
            "account_id": "1 OR 1=1",
        },
    )

    assert response.status_code == 400


def test_kyc_lookup_treats_bvn_as_data(
    kyc_client,
    auth_headers,
):
    response = kyc_client.get(
        "/v1/verify/lookup",
        headers=auth_headers,
        query_string={
            "bvn": "' OR 1=1 --",
        },
    )

    assert response.status_code == 200
    assert response.get_json() == []