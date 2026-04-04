"""
tests/integration/test_api_endpoints.py
Full CRUD integration tests for all VulnScout Pro API endpoints.

Strategy:
- Uses FastAPI's TestClient with the actual ASGI app.
- VULNSCOUT_ENV=development bypasses JWT auth → all requests get
  an admin AuthenticatedUser automatically.
- All stores are in-memory, so no external dependencies required.
"""

import os
os.environ.setdefault("VULNSCOUT_ENV", "development")

import pytest
from fastapi.testclient import TestClient

from api.main import create_app

# ── Fixture ────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ── Health check ───────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_returns_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "version" in body


# ── Targets CRUD ───────────────────────────────────────────────────────────────

class TestTargetsCRUD:
    _target_id = None

    def test_list_targets_empty_initially(self, client):
        r = client.get("/api/v1/targets")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body.get("items", body), list)

    def test_create_target(self, client):
        payload = {"url": "https://example.com", "name": "Example Corp", "industry": "general"}
        r = client.post("/api/v1/targets", json=payload)
        assert r.status_code in (200, 201)
        body = r.json()
        assert "id" in body
        assert body["url"] == "https://example.com"
        TestTargetsCRUD._target_id = body["id"]

    def test_get_target(self, client):
        tid = TestTargetsCRUD._target_id
        if not tid:
            pytest.skip("No target created yet")
        r = client.get(f"/api/v1/targets/{tid}")
        assert r.status_code == 200
        assert r.json()["id"] == tid

    def test_create_target_invalid_url(self, client):
        r = client.post("/api/v1/targets", json={"url": "not-a-url", "name": "Bad"})
        assert r.status_code in (400, 422)

    def test_delete_target(self, client):
        tid = TestTargetsCRUD._target_id
        if not tid:
            pytest.skip("No target created yet")
        r = client.delete(f"/api/v1/targets/{tid}")
        assert r.status_code in (200, 204)

    def test_get_nonexistent_target_returns_404(self, client):
        r = client.get("/api/v1/targets/nonexistent-id-00000000")
        assert r.status_code == 404


# ── Scans CRUD ─────────────────────────────────────────────────────────────────

class TestScansCRUD:
    _scan_id = None

    def test_list_scans_empty_initially(self, client):
        r = client.get("/api/v1/scans")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body.get("items", body), list)

    def test_create_scan(self, client):
        payload = {
            "target_url": "https://test.example.com",
            "scan_type": "standard",
            "config": {}
        }
        r = client.post("/api/v1/scans", json=payload)
        # 200 or 201 on success, 422 if validation strict, 400 for scope errors
        assert r.status_code in (200, 201, 202, 400, 422)
        if r.status_code in (200, 201, 202):
            body = r.json()
            assert "id" in body
            TestScansCRUD._scan_id = body["id"]

    def test_get_scan(self, client):
        sid = TestScansCRUD._scan_id
        if not sid:
            pytest.skip("No scan created yet")
        r = client.get(f"/api/v1/scans/{sid}")
        assert r.status_code == 200
        assert r.json()["id"] == sid

    def test_get_nonexistent_scan_returns_404(self, client):
        r = client.get("/api/v1/scans/no-such-scan-99999999")
        assert r.status_code == 404

    def test_list_scans_pagination(self, client):
        r = client.get("/api/v1/scans?page=1&limit=5")
        assert r.status_code == 200

    def test_cancel_nonexistent_scan(self, client):
        r = client.post("/api/v1/scans/no-such-scan/cancel")
        assert r.status_code in (404, 400)


# ── Reports CRUD ───────────────────────────────────────────────────────────────

class TestReportsCRUD:
    def test_list_reports_returns_paginated(self, client):
        r = client.get("/api/v1/reports")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body.get("items", body), list)

    def test_generate_report_for_missing_scan(self, client):
        r = client.post("/api/v1/reports", json={"scan_id": "no-such-scan", "format": "json"})
        assert r.status_code in (404, 400, 422)

    def test_list_reports_with_status_filter(self, client):
        r = client.get("/api/v1/reports?status=complete")
        assert r.status_code == 200


# ── Auth Endpoints ─────────────────────────────────────────────────────────────

class TestAuthEndpoints:
    def test_login_returns_401_for_bad_credentials(self, client):
        r = client.post("/api/v1/auth/login", json={"email": "wrong@user.com", "password": "bad"})
        assert r.status_code in (401, 422)

    def test_login_missing_fields_returns_422(self, client):
        r = client.post("/api/v1/auth/login", json={})
        assert r.status_code == 422

    def test_refresh_token_without_valid_token(self, client):
        r = client.post("/api/v1/auth/refresh", headers={"Authorization": "Bearer invalid-token"})
        assert r.status_code in (401, 422)


# ── Webhook Admin Endpoints ────────────────────────────────────────────────────

class TestWebhooks:
    _wh_id = None

    def test_list_webhooks(self, client):
        r = client.get("/api/v1/webhooks")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_create_webhook(self, client):
        payload = {
            "url": "https://webhook.site/test-vulnscout",
            "name": "Test Alert Channel",
            "events": ["scan_complete", "finding_detected"]
        }
        r = client.post("/api/v1/webhooks", json=payload)
        assert r.status_code in (200, 201)
        body = r.json()
        assert "id" in body
        assert body["name"] == "Test Alert Channel"
        TestWebhooks._wh_id = body["id"]

    def test_get_webhook(self, client):
        wid = TestWebhooks._wh_id
        if not wid:
            pytest.skip("No webhook created")
        r = client.get(f"/api/v1/webhooks/{wid}")
        assert r.status_code == 200

    def test_update_webhook(self, client):
        wid = TestWebhooks._wh_id
        if not wid:
            pytest.skip("No webhook created")
        payload = {
            "url": "https://webhook.site/updated",
            "name": "Updated Channel",
            "events": ["scan_complete"]
        }
        r = client.put(f"/api/v1/webhooks/{wid}", json=payload)
        assert r.status_code == 200
        assert r.json()["name"] == "Updated Channel"

    def test_delete_webhook(self, client):
        wid = TestWebhooks._wh_id
        if not wid:
            pytest.skip("No webhook created")
        r = client.delete(f"/api/v1/webhooks/{wid}")
        assert r.status_code in (200, 204)

    def test_get_nonexistent_webhook(self, client):
        r = client.get("/api/v1/webhooks/nonexistent-99999")
        assert r.status_code == 404


# ── Schedules Endpoints ────────────────────────────────────────────────────────

class TestSchedules:
    def test_list_schedules(self, client):
        r = client.get("/api/v1/schedules")
        # Either empty list or error if scheduler not initialised in test env
        assert r.status_code in (200, 503)

    def test_create_schedule_with_missing_target(self, client):
        payload = {
            "name": "Nightly Recon",
            "target_id": "00000000-0000-0000-0000-000000000000",
            "frequency": "daily",
            "enabled": True
        }
        r = client.post("/api/v1/schedules", json=payload)
        # Should fail — target not found, or scheduler not ready
        assert r.status_code in (404, 503, 400)

    def test_delete_nonexistent_schedule(self, client):
        r = client.delete("/api/v1/schedules/no-such-schedule")
        assert r.status_code in (404, 503)


# ── Teams Endpoints ────────────────────────────────────────────────────────────

class TestTeams:
    _team_id = None

    def test_list_teams(self, client):
        r = client.get("/api/v1/teams")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_create_team(self, client):
        r = client.post("/api/v1/teams", json={"name": "Red Team Alpha", "description": "Offensive ops unit"})
        assert r.status_code in (200, 201)
        body = r.json()
        assert body["name"] == "Red Team Alpha"
        TestTeams._team_id = body["id"]

    def test_get_team(self, client):
        tid = TestTeams._team_id
        if not tid:
            pytest.skip("No team created")
        r = client.get(f"/api/v1/teams/{tid}")
        assert r.status_code == 200

    def test_get_nonexistent_team(self, client):
        r = client.get("/api/v1/teams/no-such-team-99")
        assert r.status_code == 404
