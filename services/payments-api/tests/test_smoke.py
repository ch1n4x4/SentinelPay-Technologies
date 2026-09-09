"""Smoke tests for payments-api.

NOTE: These are happy-path only. Part of the engagement is to add tests that
demonstrate each fix actually closes the underlying vulnerability.
"""
import json
import pytest

from app.main import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"
