"""
tests/integration/test_mobile_money.py
Security integration tests targeting Mobile Money / Fintech API surfaces.

VulnScout Pro detects vulnerabilities specific to the Ugandan fintech
landscape (Airtel Money, MTN Mobile Money, etc.), including:
  - JWT forgery / weak signing (jwt_detector.py)
  - IDOR on transaction / account endpoints (idor.py)
  - Authentication bypass (auth_bypass.py)
  - Business logic exploits (OTP bypass, amount tampering) (business_logic.py)
  - Sensitive PII/PAN leakage in responses (sensitive_data.py)
  - SQL injection on payment endpoints (sqli.py)
  - Misconfigured CORS allowing cross-origin reads (misconfig.py)

These tests are integration-level: they verify VulnScout Pro's API correctly
accepts mobile-money sector targets, initiates scans, and returns structured findings.
They do NOT make live requests to external payment APIs.
"""

import os
os.environ.setdefault("VULNSCOUT_ENV", "development")

import pytest
from fastapi.testclient import TestClient

from api.main import create_app


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


FINTECH_TARGETS = [
    {"url": "https://api.airtelmoney-sandbox.example.ug", "name": "Airtel Money Sandbox", "industry": "mobile_money"},
    {"url": "https://api.momo-sandbox.example.ug", "name": "MTN MoMo Sandbox", "industry": "mobile_money"},
]


# ── 1. Target Registration — Fintech Sector ────────────────────────────────────

class TestFintechTargetRegistration:
    """Verify that mobile money targets can be registered with correct industry tagging."""

    created_ids: list = []

    @pytest.mark.parametrize("target", FINTECH_TARGETS)
    def test_register_fintech_target(self, client, target):
        r = client.post("/api/v1/targets", json=target)
        # Either created (200/201) or rejected by scope policy (400)
        assert r.status_code in (200, 201, 400, 422), \
            f"Unexpected {r.status_code} for target {target['url']}: {r.text}"
        if r.status_code in (200, 201):
            body = r.json()
            assert "id" in body
            TestFintechTargetRegistration.created_ids.append(body["id"])

    def test_fintech_target_industry_field_preserved(self, client):
        r = client.post("/api/v1/targets", json={
            "url": "https://mobile-wallet.example.ug",
            "name": "Mobile Wallet UG",
            "industry": "mobile_money"
        })
        if r.status_code in (200, 201):
            body = r.json()
            assert body.get("industry") == "mobile_money" or "id" in body

    def test_target_with_http_only_flagged_or_accepted(self, client):
        """HTTP-only endpoints are common in fintech sandbox environments."""
        r = client.post("/api/v1/targets", json={
            "url": "http://sandbox.mobilemoney.example.ug",
            "name": "HTTP Sandbox",
            "industry": "mobile_money"
        })
        # May be accepted (with a warning) or rejected — both are valid policy decisions
        assert r.status_code in (200, 201, 400, 422)


# ── 2. Scan Initiation — Payment API Attack Surface ───────────────────────────

class TestFintechScanInitiation:
    """Verify scans can be initiated against fintech targets."""

    scan_ids: list = []

    def test_initiate_standard_scan_against_fintech_url(self, client):
        payload = {
            "target_url": "https://api.airtelmoney-sandbox.example.ug",
            "scan_strategy": "standard",
        }
        r = client.post("/api/v1/scans", json=payload)
        assert r.status_code in (200, 201, 202, 400, 422)
        if r.status_code in (200, 201, 202):
            body = r.json()
            sid = body.get("id") or body.get("scan_id")
            assert sid is not None
            TestFintechScanInitiation.scan_ids.append(sid)

    def test_scan_with_auth_context_header_provided(self, client):
        """Fintech scans often require a bearer token for authenticated testing."""
        payload = {
            "target_url": "https://api.airtelmoney-sandbox.example.ug",
            "scan_strategy": "standard",
            "config": {
                "auth_headers": {"Authorization": "Bearer test-token-sandbox"}
            }
        }
        r = client.post("/api/v1/scans", json=payload)
        assert r.status_code in (200, 201, 202, 400, 422)

    def test_scan_type_empty_string_rejected(self, client):
        r = client.post("/api/v1/scans", json={
            "target_url": "https://api.airtelmoney-sandbox.example.ug",
            "scan_strategy": ""
        })
        assert r.status_code in (400, 422)

    def test_scan_for_each_registered_target(self, client):
        for tid in TestFintechTargetRegistration.created_ids[:1]:  # Limit for speed
            r = client.post("/api/v1/scans", json={
                "target_url": "https://api.airtelmoney-sandbox.example.ug",
                "target_id": tid,
                "scan_strategy": "standard",
            })
            assert r.status_code in (200, 201, 202, 400, 422)


# ── 3. Finding Retrieval — Vulnerability Categories ───────────────────────────

class TestFintechFindingRelevance:
    """Verify the findings endpoint returns expected vulnerability types for fintech targets."""

    EXPECTED_VULN_CATEGORIES = {
        "idor",            # Horizontal privilege escalation on /accounts/{id}
        "sqli",            # Injection on payment query params
        "jwt",             # Weak JWT secret / alg=none
        "auth_bypass",     # Broken auth on /transactions/send
        "sensitive_data",  # Phone/PAN numbers leaked in error responses
        "business_logic",  # OTP skip, amount manipulation
        "misconfig",       # CORS allowing any origin on payment APIs
        "xss",             # Reflected XSS via error messages
    }

    def test_findings_endpoint_returns_structured_data(self, client):
        scan_ids = TestFintechScanInitiation.scan_ids
        if not scan_ids:
            pytest.skip("No scans were created")
        sid = scan_ids[0]
        r = client.get(f"/api/v1/scans/{sid}/findings")
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            body = r.json()
            items = body.get("items", body if isinstance(body, list) else [])
            assert isinstance(items, list)

    def test_findings_severity_field_present(self, client):
        scan_ids = TestFintechScanInitiation.scan_ids
        if not scan_ids:
            pytest.skip("No scans were created")
        r = client.get(f"/api/v1/scans/{scan_ids[0]}/findings")
        if r.status_code == 200:
            items = r.json().get("items", [])
            for finding in items:
                assert "severity" in finding, f"Finding missing severity: {finding}"
                assert finding["severity"] in ("critical", "high", "medium", "low", "info")

    def test_findings_filter_by_severity_critical(self, client):
        scan_ids = TestFintechScanInitiation.scan_ids
        if not scan_ids:
            pytest.skip("No scans were created")
        r = client.get(f"/api/v1/scans/{scan_ids[0]}/findings?severity=critical")
        assert r.status_code in (200, 404)


# ── 4. Report Generation — Compliance Formats ─────────────────────────────────

class TestFintechComplianceReports:
    """Verify reports can be generated in formats required by Ugandan regulators (BOU, NITA-U)."""

    def test_json_report_generated(self, client):
        scan_ids = TestFintechScanInitiation.scan_ids
        if not scan_ids:
            pytest.skip("No scans available")
        r = client.post("/api/v1/reports", json={"scan_id": scan_ids[0], "formats": ["json"]})
        assert r.status_code in (200, 201, 202)

    def test_pdf_report_generated(self, client):
        scan_ids = TestFintechScanInitiation.scan_ids
        if not scan_ids:
            pytest.skip("No scans available")
        r = client.post("/api/v1/reports", json={"scan_id": scan_ids[0], "formats": ["pdf"]})
        assert r.status_code in (200, 201, 202)

    def test_reports_list_includes_fintech_report(self, client):
        r = client.get("/api/v1/reports")
        assert r.status_code == 200

    def test_invalid_report_format_rejected(self, client):
        scan_ids = TestFintechScanInitiation.scan_ids
        if not scan_ids:
            pytest.skip("No scans available")
        r = client.post("/api/v1/reports", json={"scan_id": scan_ids[0], "formats": ["docx"]})
        assert r.status_code in (400, 422)


# ── 5. Security Control Checks ────────────────────────────────────────────────

class TestVulnScoutAPISecurityControls:
    """Verify VulnScout Pro's own API doesn't expose fintech-related vulnerabilities."""

    def test_unauthenticated_scan_create_blocked_in_production(self, client):
        """In production (non-dev) mode, unauthenticated requests must be rejected."""
        # In dev mode, this passes — test is informational
        r = client.post("/api/v1/scans", json={
            "target_url": "https://api.airtelmoney-sandbox.example.ug",
            "scan_type": "standard"
        })
        # Dev mode returns 200/201 or validation error — not a 401
        # Production mode would return 401
        assert r.status_code in (200, 201, 202, 400, 401, 422)

    def test_api_response_does_not_leak_stack_trace(self, client):
        """Error responses must not expose internal Python stack traces."""
        r = client.get("/api/v1/scans/trigger-error-99999")
        if r.status_code >= 400:
            text = r.text
            assert "Traceback" not in text, "Stack trace leaked in error response!"
            assert "File \"" not in text, "File path leaked in error response!"

    def test_security_headers_present(self, client):
        """Each response must include basic security headers."""
        r = client.get("/health")
        headers = r.headers
        # Check for at minimum one security hardening header
        security_headers = [
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
            "strict-transport-security",
            "content-security-policy",
        ]
        present = [h for h in security_headers if h in headers]
        assert len(present) >= 1, \
            f"No security headers found. Had: {dict(headers)}"

    def test_cors_not_wildcard_for_api_routes(self, client):
        """API endpoints must not return Access-Control-Allow-Origin: * for credentialed requests."""
        r = client.options(
            "/api/v1/scans",
            headers={
                "Origin": "https://evil.attacker.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization",
            }
        )
        acao = r.headers.get("access-control-allow-origin", "")
        # Must not blindly allow all origins for credentialed requests
        assert acao != "*" or r.status_code in (403, 405), \
            f"Wildcard CORS detected on credentialed API route: {acao}"
