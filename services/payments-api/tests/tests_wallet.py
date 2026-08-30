"""Tests for wallet operations, including concurrency and race conditions."""
from concurrent.futures import ThreadPoolExecutor

def test_wallet_debit_race_condition_regression(client, valid_token):
    """
    Regression test for V-APP-05 (Wallet Race Condition).

    REMEDIATION START: V-APP-05 Concurrent Execution Test
    This test verifies the row-level locking (SELECT ... FOR UPDATE) implemented 
    in the debit_wallet route. It fires two simultaneous debit requests against an 
    account with a starting balance of 100.00, attempting to withdraw 80.00 twice[cite: 13].
    Because the backend locks the row, the database forces the requests to evaluate 
    sequentially rather than reading a stale pre-balance[cite: 13, 14].
    """
    auth_header = {"Authorization": f"Bearer {valid_token}"}
    
    def debit():
        return client.post(
            "/v1/wallets/1/debit",
            headers=auth_header,
            json={"amount": "80.00"},
        )

    # Use ThreadPoolExecutor to fire the requests simultaneously[cite: 13]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: debit(), range(2)))

    # Exactly one request must succeed (200 OK), and the second must 
    # fail due to insufficient funds (400 Bad Request)[cite: 13].
    assert sorted(r.status_code for r in responses) == [200, 400]
    # REMEDIATION END