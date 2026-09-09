"""Smoke test for kyc-api."""
import pytest
from app.main import create_app


@pytest.fixture
def client():
    app = create_app()
    return app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
