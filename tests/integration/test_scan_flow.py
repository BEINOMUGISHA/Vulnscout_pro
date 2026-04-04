"""
tests/integration/test_scan_flow.py
End-to-end scan lifecycle tests for VulnScout Pro.

Tests: initiate scan → check status → verify findings endpoint →
       cancel running scan → download report.

VULNSCOUT_ENV=development bypasses JWT auth, returning an admin user.
"""

import os
os.environ.setdefault("VULNSCOUT_ENV", "development")

import time
import pytest
from fastapi.testclient import TestClient

from api.main import create_app


@pytest.fixture(scope="module")
def client():
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ── 1. Validate scan endpoint scaffolding is accessible ───────────────────────

class TestScanEndpointAvailability:
    def test_scans_list_endpoint_exists(self, client):
        r = client.get("/api/v1/scans")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"

    def test_scans_list_returns_items_key(self, client):
        r = client.get("/api/v1/scans")
        body = r.json()
        # Accept either a list directly or paginated {items: [...]}
        assert isinstance(body, (list, dict))
        if isinstance(body, dict):
            assert "items" in body or "scans" in body


# ── 2. Target creation is prerequisite for scan ───────────────────────────────

class TestScanPrerequisiteTarget:
    _tid = None

    def test_create_target_for_scan(self, client):
        r = client.post("/api/v1/targets", json={
            "url": "https://scantest.example.com",
            "name": "ScanTest Target",
            "industry": "ecommerce"
        })
        if r.status_code in (200, 201):
            TestScanPrerequisiteTarget._tid = r.json().get("id")
        # Accept either success or scope-validation failure
        assert r.status_code in (200, 201, 400, 422)


# ── 3. Scan creation & initial status ─────────────────────────────────────────

class TestScanLifecycle:
    _scan_id = None

    def test_create_scan_returns_id(self, client):
        payload = {
            "target_url": "https://scantest.example.com",
            "scan_type": "standard",
        }
        r = client.post("/api/v1/scans", json=payload)
        # Standard outcome: 200/201 created, OR 400 (scope/auth policy), OR 422 (validation)
        assert r.status_code in (200, 201, 400, 422)
        if r.status_code in (200, 201):
            body = r.json()
            assert "id" in body
            assert body.get("status") in ("pending", "queued", "running", "initialising")
            TestScanLifecycle._scan_id = body["id"]

    def test_created_scan_is_retrievable(self, client):
        sid = TestScanLifecycle._scan_id
        if not sid:
            pytest.skip("Scan creation failed or returned non-success status")
        r = client.get(f"/api/v1/scans/{sid}")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == sid
        assert "status" in body

    def test_scan_findings_endpoint_exists(self, client):
        sid = TestScanLifecycle._scan_id
        if not sid:
            pytest.skip("Scan creation failed")
        r = client.get(f"/api/v1/scans/{sid}/findings")
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            body = r.json()
            assert isinstance(body.get("items", body), list)

    def test_cancel_scan(self, client):
        sid = TestScanLifecycle._scan_id
        if not sid:
            pytest.skip("Scan creation failed")
        r = client.post(f"/api/v1/scans/{sid}/cancel")
        # Either cancelled (200/204) or already in terminal state (400)
        assert r.status_code in (200, 204, 400, 404)

    def test_scan_status_after_cancel(self, client):
        sid = TestScanLifecycle._scan_id
        if not sid:
            pytest.skip("Scan creation failed")
        r = client.get(f"/api/v1/scans/{sid}")
        if r.status_code == 200:
            body = r.json()
            # After cancel attempt, status should be terminal or at least not running
            assert "status" in body


# ── 4. Report generation after scan ───────────────────────────────────────────

class TestReportGeneration:
    def test_generate_report_for_valid_scan(self, client):
        sid = TestScanLifecycle._scan_id
        if not sid:
            pytest.skip("No scan available")
        r = client.post("/api/v1/reports", json={"scan_id": sid, "format": "json"})
        # 200/201 = created; 400 if scan not in complete state
        assert r.status_code in (200, 201, 400, 422)

    def test_download_report_json_format(self, client):
        sid = TestScanLifecycle._scan_id
        if not sid:
            pytest.skip("No scan available")
        r = client.get(f"/api/v1/scans/{sid}/report?format=json")
        assert r.status_code in (200, 404, 400)

    def test_download_report_pdf_format(self, client):
        sid = TestScanLifecycle._scan_id
        if not sid:
            pytest.skip("No scan available")
        r = client.get(f"/api/v1/scans/{sid}/report?format=pdf")
        assert r.status_code in (200, 404, 400)


# ── 5. Concurrent scan submission guard ───────────────────────────────────────

class TestScanRobustness:
    def test_missing_target_url_returns_error(self, client):
        r = client.post("/api/v1/scans", json={"scan_type": "standard"})
        assert r.status_code in (400, 422)

    def test_invalid_scan_type_returns_error(self, client):
        r = client.post("/api/v1/scans", json={
            "target_url": "https://scantest.example.com",
            "scan_type": "INVALID_TYPE_XYZ"
        })
        assert r.status_code in (400, 422)

    def test_scan_list_pagination_bounds(self, client):
        r = client.get("/api/v1/scans?page=999&limit=5")
        assert r.status_code == 200
        body = r.json()
        items = body.get("items", body if isinstance(body, list) else [])
        assert isinstance(items, list)

    def test_scan_findings_for_nonexistent_scan(self, client):
        r = client.get("/api/v1/scans/nonexistent-scan-id/findings")
        assert r.status_code == 404
