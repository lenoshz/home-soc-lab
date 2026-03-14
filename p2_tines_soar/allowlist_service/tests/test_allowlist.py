"""Tests for the allowlist service."""
import pytest
from p2_tines_soar.allowlist_service.app import app, _ALLOWLIST


@pytest.fixture(autouse=True)
def clear_allowlist():
    """Clear the allowlist before each test."""
    _ALLOWLIST.clear()
    yield
    _ALLOWLIST.clear()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestHealth:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"


class TestListAllowlist:
    def test_empty_allowlist(self, client):
        resp = client.get("/allowlist")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_returns_entries(self, client):
        client.post("/allowlist", json={"entry": "8.8.8.8", "type": "ip", "reason": "DNS"})
        resp = client.get("/allowlist")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["entry"] == "8.8.8.8"


class TestAddToAllowlist:
    def test_add_ip_entry(self, client):
        resp = client.post("/allowlist", json={"entry": "1.2.3.4", "type": "ip", "reason": "test"})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["entry"]["entry"] == "1.2.3.4"
        assert data["entry"]["type"] == "ip"

    def test_add_domain_entry(self, client):
        resp = client.post("/allowlist", json={"entry": "example.com", "type": "domain", "reason": "trusted"})
        assert resp.status_code == 201
        assert resp.get_json()["entry"]["type"] == "domain"

    def test_add_duplicate_is_idempotent(self, client):
        client.post("/allowlist", json={"entry": "1.2.3.4", "type": "ip"})
        resp = client.post("/allowlist", json={"entry": "1.2.3.4", "type": "ip"})
        assert resp.status_code == 200
        assert "already exists" in resp.get_json()["message"]
        # Should still only have 1 entry
        assert len(_ALLOWLIST) == 1

    def test_missing_entry_returns_400(self, client):
        resp = client.post("/allowlist", json={"type": "ip"})
        assert resp.status_code == 400

    def test_entry_has_added_at(self, client):
        resp = client.post("/allowlist", json={"entry": "9.9.9.9", "type": "ip"})
        assert "added_at" in resp.get_json()["entry"]


class TestRemoveFromAllowlist:
    def test_remove_existing_entry(self, client):
        client.post("/allowlist", json={"entry": "1.2.3.4", "type": "ip"})
        resp = client.delete("/allowlist/1.2.3.4")
        assert resp.status_code == 200
        assert len(_ALLOWLIST) == 0

    def test_remove_nonexistent_returns_404(self, client):
        resp = client.delete("/allowlist/9.9.9.9")
        assert resp.status_code == 404


class TestCheckAllowlist:
    def test_check_allowed_entry(self, client):
        client.post("/allowlist", json={"entry": "8.8.8.8", "type": "ip"})
        resp = client.get("/allowlist/check/8.8.8.8")
        assert resp.status_code == 200
        assert resp.get_json()["allowed"] is True

    def test_check_not_allowed_entry(self, client):
        resp = client.get("/allowlist/check/1.1.1.1")
        assert resp.status_code == 200
        assert resp.get_json()["allowed"] is False
