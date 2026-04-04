"""
idor.py — Insecure Direct Object Reference (IDOR) Detector

Covers:
  - Sequential integer ID enumeration in URL paths and query params
  - UUID/GUID enumeration (v4 random, but some apps use sequential UUIDs)
  - Account/member number patterns (SACCO, MFI, NSSF, URA TIN)
  - Transaction reference IDOR (mobile money, banking)
  - Document IDOR (KYC files, tax returns, certificates)
  - Horizontal privilege escalation (access other user's data)

EA context:
  IDORs are the most common finding in Ugandan fintech and government
  portals. SACCO member IDs, NSSF member numbers, MTN MoMo transaction
  references, and URA TIN numbers all follow predictable formats that
  enable mass enumeration of customer data.
"""

from __future__ import annotations

import re
import uuid
from typing import List, Optional, Tuple

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload, DetectionHit
from core.models.finding import VulnType, Finding, FindingEvidence

_CVSS_IDOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"   # 7.1
_CVSS_IDOR_HIGH = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"  # 8.1

# Response patterns indicating user data was returned
_USER_DATA_PATTERN = re.compile(
    r"""(?xi)
    (
        "email"\s*:\s*"[^"]+@[^"]+"|
        "phone"\s*:|
        "msisdn"\s*:|
        "username"\s*:|
        "account_number"\s*:|
        "balance"\s*:|
        "amount"\s*:|
        "transaction"\s*:|
        "member_number"\s*:|
        "tin"\s*:|
        "nin"\s*:|
        "name"\s*:\s*"[A-Z][a-z]+\s+[A-Z]|
        "date_of_birth"\s*:|
        "address"\s*:|
        account.*balance|
        wallet.*balance|
        statement|
        profile|
        personal.*details
    )
    """,
    re.IGNORECASE,
)

# Patterns for EA-specific identifier formats
_EA_ID_PATTERNS = {
    "sacco_member":   re.compile(r"SCC\d{5}|MFI\d{5}|SACCO\d+", re.IGNORECASE),
    "nssf_member":    re.compile(r"NSS[F]?\d{6,10}", re.IGNORECASE),
    "ura_tin":        re.compile(r"\b\d{10}\b"),   # URA TIN is 10 digits
    "mtn_momo_ref":   re.compile(r"[A-Z]{2}\d{6}\.\d{4}\.\d{6}"),  # CI240101.0000.000001
    "airtel_txn":     re.compile(r"CI\d{6}\.\d{4}\.\d{6}"),
    "nira_nin":       re.compile(r"CM[A-Z0-9]{14}", re.IGNORECASE),  # Uganda NIN format
}

# IDOR-susceptible parameter names
_IDOR_PARAMS = frozenset([
    "id", "user_id", "userId", "account_id", "accountId",
    "member_id", "memberId", "customer_id", "customerId",
    "order_id", "orderId", "transaction_id", "transactionId",
    "reference", "ref", "invoice_id", "invoiceId",
    "document_id", "documentId", "file_id", "fileId",
    "receipt_id", "receiptId", "payment_id", "paymentId",
    "profile_id", "profileId", "record_id", "recordId",
    # EA-specific
    "tin", "nin", "msisdn", "phone", "agent_id", "agentId",
    "merchant_id", "merchantId", "policy_id", "policyId",
    "loan_id", "loanId", "account_number", "accountNumber",
])


class IDORDetector(BaseDetector):

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="idor",
            name="Insecure Direct Object Reference",
            description="Detects IDOR via ID enumeration in URLs, query params, and EA-specific identifiers",
            vuln_types=[VulnType.IDOR],
            owasp_categories=["A01:2021 – Broken Access Control"],
            estimated_requests_per_endpoint=10,
        )

    @property
    def payloads(self) -> List[Payload]:
        # IDOR payloads are generated dynamically from parameter context.
        # This base list covers fixed test cases.
        return []

    async def detect(self, target, crawl_result, injector) -> list:
        findings = []

        # Test each parameter that looks like an object reference
        for param in crawl_result.parameters:
            if not self._is_idor_candidate(param):
                continue

            # Get the baseline response first
            baseline = await self._get_baseline(injector, crawl_result, param)
            if baseline is None:
                continue

            # Generate ID variants to enumerate
            test_ids = self._generate_test_ids(param.value, param.name)

            for test_id in test_ids:
                finding = await self._test_idor(
                    injector, crawl_result, param, test_id, baseline
                )
                if finding:
                    finding.ea_context = self._build_ea_ctx(target, param)
                    findings.append(finding)
                    break   # One confirmed IDOR per param is enough

        # Also check URL path segments for numeric IDs
        path_findings = await self._check_path_ids(injector, crawl_result, target)
        findings.extend(path_findings)

        return findings

    async def _get_baseline(self, injector, crawl_result, param) -> Optional[str]:
        """Fetch the baseline response with the original parameter value."""
        from core.scanner.injector import InjectionRequest, PayloadEncoding
        req = InjectionRequest(
            url=crawl_result.url,
            method=crawl_result.method,
            parameter_name=param.name,
            parameter_location=param.location,
            original_value=param.value,
            payload=param.value,
            encoding=PayloadEncoding.PLAIN,
        )
        try:
            resp = await injector.inject(req)
            return resp.body if resp.success else None
        except Exception:
            return None

    async def _test_idor(
        self,
        injector,
        crawl_result,
        param,
        test_id: str,
        baseline_body: str,
    ) -> Optional[Finding]:
        """Test a single ID value and check for IDOR evidence."""
        from core.scanner.injector import InjectionRequest, PayloadEncoding

        req = InjectionRequest(
            url=crawl_result.url,
            method=crawl_result.method,
            parameter_name=param.name,
            parameter_location=param.location,
            original_value=param.value,
            payload=test_id,
            encoding=PayloadEncoding.PLAIN,
        )
        try:
            resp = await injector.inject(req)
        except Exception:
            return None

        if not resp.success:
            return None

        if resp.status_code in (401, 403, 404):
            return None   # Properly rejected — not an IDOR

        # Check if the response contains user data and differs from baseline
        has_data = bool(_USER_DATA_PATTERN.search(resp.body))
        is_different = abs(len(resp.body) - len(baseline_body)) > 50
        status_ok = resp.status_code in (200, 201)

        if not (has_data and status_ok):
            return None

        # Confirm it returned *different* data (not just the same user's data)
        if not is_different and resp.body[:200] == baseline_body[:200]:
            return None

        matched = _USER_DATA_PATTERN.search(resp.body)
        matched_text = matched.group(0)[:100] if matched else ""

        self._log_hit(self.meta.detector_id, crawl_result.url, param.name, f"id={test_id}")

        evidence = FindingEvidence(
            request_method=crawl_result.method,
            request_url=crawl_result.url,
            injected_parameter=param.name,
            injected_payload=test_id,
            response_status=resp.status_code,
            response_body_excerpt=self._safe_excerpt(resp.body, matched_text),
            matched_pattern=_USER_DATA_PATTERN.pattern[:80],
        )

        # Higher CVSS if payment data is exposed
        cvss = _CVSS_IDOR_HIGH if self._is_payment_data(resp.body) else _CVSS_IDOR

        return Finding(
            id=str(uuid.uuid4()),
            url=crawl_result.url,
            parameter_name=param.name,
            parameter_location=param.location,
            vuln_type=VulnType.IDOR,
            cvss_vector=cvss,
            confidence=0.6,
            evidence=evidence,
            evidence_pattern=_USER_DATA_PATTERN.pattern[:80],
            evidence_status_code=resp.status_code,
            injection_request=req,
        )

    async def _check_path_ids(self, injector, crawl_result, target) -> list:
        """
        Check numeric segments in URL path for IDOR.
        E.g. /api/users/1042 → try /api/users/1043
        """
        from urllib.parse import urlparse, urlunparse
        findings = []
        parsed = urlparse(crawl_result.url)
        path_parts = parsed.path.split("/")

        for i, part in enumerate(path_parts):
            if not re.match(r"^\d{1,10}$", part):
                continue

            original_id = int(part)
            test_id = str(original_id + 1)
            new_parts = path_parts.copy()
            new_parts[i] = test_id
            new_url = urlunparse(parsed._replace(path="/".join(new_parts)))

            from core.scanner.injector import InjectionRequest, PayloadEncoding
            req = InjectionRequest(
                url=new_url,
                method=crawl_result.method,
                parameter_name=f"path_segment_{i}",
                parameter_location="path",
                original_value=str(original_id),
                payload=test_id,
                encoding=PayloadEncoding.PLAIN,
            )
            try:
                resp = await injector.inject(req)
            except Exception:
                continue

            if not resp.success or resp.status_code in (401, 403, 404):
                continue

            if _USER_DATA_PATTERN.search(resp.body) and resp.status_code == 200:
                self._log_hit(self.meta.detector_id, new_url, f"path[{i}]", f"id={test_id}")
                evidence = FindingEvidence(
                    request_method=crawl_result.method,
                    request_url=new_url,
                    injected_parameter=f"path_id[{part}]",
                    injected_payload=test_id,
                    response_status=resp.status_code,
                    response_body_excerpt=resp.body[:500],
                    matched_pattern="path ID enumeration",
                )
                cvss = _CVSS_IDOR_HIGH if self._is_payment_data(resp.body) else _CVSS_IDOR
                f = Finding(
                    id=str(uuid.uuid4()),
                    url=new_url,
                    parameter_name=f"path_id",
                    parameter_location="path",
                    vuln_type=VulnType.IDOR,
                    cvss_vector=cvss,
                    confidence=0.65,
                    evidence=evidence,
                )
                f.ea_context = self._build_ea_ctx(target, None)
                findings.append(f)
        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_idor_candidate(param) -> bool:
        """Is this parameter a likely object reference?"""
        name_lower = param.name.lower()
        return (
            name_lower in {p.lower() for p in _IDOR_PARAMS}
            or re.search(r"(_id|Id|ID)$", param.name) is not None
            or (param.value and re.match(r"^\d{1,12}$", param.value))
        )

    @staticmethod
    def _generate_test_ids(current_value: str, param_name: str) -> List[str]:
        """Generate plausible IDOR test IDs from the current value."""
        ids = []

        # Numeric increment/decrement
        if re.match(r"^\d+$", current_value or ""):
            n = int(current_value)
            ids += [str(n + 1), str(n - 1), str(n + 10), "1", "2", "100"]

        # EA-specific: SACCO member number pattern
        if re.match(r"^SCC\d+$", current_value or "", re.IGNORECASE):
            n = int(current_value[3:])
            ids += [f"SCC{n+1:05d}", f"SCC{n-1:05d}", "SCC00001"]

        # UUID — try a null UUID and a known-test UUID
        if re.match(r"^[0-9a-f-]{36}$", current_value or "", re.IGNORECASE):
            ids += [
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            ]

        # MTN MoMo reference pattern
        if re.match(r"^[A-Z]{2}\d{6}\.\d{4}\.\d{6}$", current_value or ""):
            ids += ["CI240101.0000.000001", "CI240101.0000.000002"]

        return ids[:6]   # Cap at 6 test IDs per parameter

    @staticmethod
    def _is_payment_data(body: str) -> bool:
        return bool(re.search(
            r"(?i)(balance|amount|transaction|payment|wallet|float|commission)",
            body,
        ))

    @staticmethod
    def _build_ea_ctx(target, param) -> object:
        from core.models.finding import EAContext
        is_ea = getattr(target, "is_ea_target", False)
        is_payment = param and param.name.lower() in (
            "transaction_id", "transactionid", "reference", "payment_id"
        )
        return EAContext(
            ea_relevant=is_ea,
            attack_impact=(
                "IDOR on payment/transaction IDs exposes other users' "
                "financial records — a direct PDPA violation."
            ) if is_payment else (
                "IDOR exposes personally identifiable information of other users."
            ),
            max_regulatory_multiplier=1.4 if is_payment else 1.3,
            regulatory_requirements=[
                {
                    "body": "NITA-U",
                    "requirement_id": "NITA-U-PDPA-2019",
                    "description": "Uganda Data Protection and Privacy Act 2019",
                    "risk_multiplier": 1.35,
                    "penalty": "Criminal liability + UGX 500M fine",
                }
            ] if is_ea else [],
        )