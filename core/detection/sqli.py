"""
sqli.py — SQL Injection Detector

Covers three SQLi variants:
  1. Error-based   — DB error messages in response body
  2. Boolean-based — structural response differences (true vs false conditions)
  3. Time-based blind — response delay with SLEEP/WAITFOR/pg_sleep
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload
from core.models.finding import VulnType


# ── Error signatures ───────────────────────────────────────────────────────────

_DB_ERRORS = (
    # MySQL / MariaDB
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark after the character string",
    r"supplied argument is not a valid mysql",
    r"mysql_fetch_array\(\)",
    r"mysql_num_rows\(\)",
    r"mysql_fetch_object\(\)",
    # PostgreSQL
    r"pg_query\(\)|pg_exec\(\)",
    r"syntax error at or near",
    r"invalid input syntax for",
    r"column .* does not exist",
    # SQLite
    r"sqlite3\.operationalerror",
    r"sqlite_master",
    r"no such table",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlserver",
    r"\[microsoft\]\[odbc",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    # Generic
    r"sql syntax.*mysql|mysql.*sql syntax",
    r"warning.*\Wpg_",
    r"valid mysql result",
    r"mysql_query\(\)",
    r"numrows\(\)",
    r"pdo.*exception",
    r"dbal.*exception",
)

_DB_ERROR_PATTERN = "(?i)(" + "|".join(_DB_ERRORS) + ")"

_FP_PATTERN = (
    r"(?i)(invalid input|incorrect password|"
    r"please enter|field is required|"
    r"captcha|recaptcha|cloudflare)"
)

# ── CVSS vectors ───────────────────────────────────────────────────────────────

_CVSS_ERROR    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
_CVSS_BLIND    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
_CVSS_BOOLEAN  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 8.1


class SQLiDetector(BaseDetector):

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="sqli",
            name="SQL Injection",
            description="Detects error-based, boolean-based, and time-based blind SQL injection",
            vuln_types=[VulnType.SQLI, VulnType.SQLI_ERROR, VulnType.SQLI_BLIND],
            owasp_categories=["A03:2021 – Injection"],
            estimated_requests_per_endpoint=18,
        )

    @property
    def payloads(self) -> List[Payload]:
        return [
            # ── Error-based ────────────────────────────────────────────────────
            Payload(
                value="'",
                description="Single quote — triggers syntax error",
                evidence_pattern=_DB_ERROR_PATTERN,
                false_positive_pattern=_FP_PATTERN,
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.3,
            ),
            Payload(
                value='"',
                description="Double quote — triggers syntax error",
                evidence_pattern=_DB_ERROR_PATTERN,
                false_positive_pattern=_FP_PATTERN,
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.3,
            ),
            Payload(
                value="'--",
                description="Single quote with SQL comment",
                evidence_pattern=_DB_ERROR_PATTERN,
                false_positive_pattern=_FP_PATTERN,
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.35,
            ),
            Payload(
                value="' OR '1'='1",
                description="Classic OR tautology",
                evidence_pattern=_DB_ERROR_PATTERN,
                false_positive_pattern=_FP_PATTERN,
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.4,
            ),
            Payload(
                value="1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))",
                description="MSSQL type conversion error (T24 banking core probe)",
                evidence_pattern=r"(?i)(conversion failed|cannot convert|mssql|sqlserver)",
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.4,
            ),
            Payload(
                value="' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
                description="MySQL extractvalue() error-based",
                evidence_pattern=r"XPATH syntax error",
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.45,
            ),
            Payload(
                value="' AND updatexml(1,concat(0x7e,(SELECT user())),1)--",
                description="MySQL updatexml() error-based",
                evidence_pattern=r"XPATH syntax error",
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.45,
            ),
            # WAF Evasion / Fingerprinting
            Payload(
                value="'/*!50000AND*/(SELECT 1)=1--",
                description="MySQL version-heavy comment evasion",
                evidence_pattern=_DB_ERROR_PATTERN,
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.5,
            ),
            Payload(
                value="1' UNION SELECT @@version,user(),database()--",
                description="MySQL UNION-based fingerprinting",
                evidence_pattern=r"(?i)(ubuntu|debian|centos|mariadb|mysql)",
                vuln_type=VulnType.SQLI_ERROR,
                cvss_vector=_CVSS_ERROR,
                confidence_boost=0.55,
            ),

            # ── Time-based blind ───────────────────────────────────────────────
            Payload(
                value="' AND SLEEP(5)--",
                description="MySQL SLEEP — time-based blind",
                evidence_pattern="",
                vuln_type=VulnType.SQLI_BLIND,
                cvss_vector=_CVSS_BLIND,
                confidence_boost=0.4,
                is_blind=True,
                delay_seconds=5.0,
            ),
            Payload(
                value="1; WAITFOR DELAY '0:0:5'--",
                description="MSSQL WAITFOR — time-based blind (T24/banking)",
                evidence_pattern="",
                vuln_type=VulnType.SQLI_BLIND,
                cvss_vector=_CVSS_BLIND,
                confidence_boost=0.4,
                is_blind=True,
                delay_seconds=5.0,
            ),
            Payload(
                value="' AND pg_sleep(5)--",
                description="PostgreSQL pg_sleep — time-based blind",
                evidence_pattern="",
                vuln_type=VulnType.SQLI_BLIND,
                cvss_vector=_CVSS_BLIND,
                confidence_boost=0.4,
                is_blind=True,
                delay_seconds=5.0,
            ),
            Payload(
                value="' AND RANDOMBLOB(500000000/1)--",
                description="SQLite heavy computation — time-based blind",
                evidence_pattern="",
                vuln_type=VulnType.SQLI_BLIND,
                cvss_vector=_CVSS_BLIND,
                confidence_boost=0.35,
                is_blind=True,
                delay_seconds=3.0,
            ),

            # ── Boolean-based (differential) ──────────────────────────────────
            Payload(
                value="' AND '1'='1' --",
                description="Boolean true condition",
                evidence_pattern=r"(?i)(welcome|dashboard|success|results|found)",
                false_positive_pattern=r"(?i)(login|sign in|error|invalid)",
                vuln_type=VulnType.SQLI,
                cvss_vector=_CVSS_BOOLEAN,
                confidence_boost=0.2,
            ),
            Payload(
                value="1 AND 1=1",
                description="Numeric true condition",
                evidence_pattern="", # Handled by differential logic
                vuln_type=VulnType.SQLI,
                cvss_vector=_CVSS_BOOLEAN,
                confidence_boost=0.15,
            ),
            Payload(
                value="1' AND '1'='1",
                description="String true condition",
                evidence_pattern="", # Handled by differential logic
                vuln_type=VulnType.SQLI,
                cvss_vector=_CVSS_BOOLEAN,
                confidence_boost=0.15,
            ),

        ]

    async def detect(self, target, crawl_result, injector) -> list:
        findings = []

        async def test_parameter(param):
            if not self._should_test_parameter(param, crawl_result):
                return None
            if param.location == "header" and param.name not in (
                "User-Agent", "Referer", "X-Forwarded-For"
            ):
                return None

            # 1. Establish baseline for this parameter
            baseline = await self._get_baseline(injector, crawl_result, param)

            # Test payloads for this parameter in parallel
            async def test_one_payload(payload):
                if payload.vuln_type == VulnType.SQLI:
                    return await self._test_boolean_differential(injector, crawl_result, param, payload, baseline)
                else:
                    return await self._test_payload(injector, crawl_result, param, payload, baseline)

            # Run all payloads for this parameter concurrently
            payload_results = await asyncio.gather(*[test_one_payload(p) for p in self.payloads], return_exceptions=True)
            
            param_findings = []
            for hit in payload_results:
                if isinstance(hit, DetectionHit) and hit:
                    self._log_hit(self.meta.detector_id, crawl_result.url, param.name, hit.matched_text)
                    ea_ctx = self._build_ea_context(target, crawl_result, hit.payload)
                    param_findings.append(self._build_finding(hit, ea_context=ea_ctx))
                    # We could break here if we only want one finding per parameter, 
                    # but with gather we already ran them all.
            
            return param_findings

        # RUN ALL PARAMETERS IN PARALLEL
        results = await asyncio.gather(*[test_parameter(p) for p in crawl_result.parameters], return_exceptions=True)
        
        for res in results:
            if isinstance(res, list):
                findings.extend(res)

        return findings

    async def _test_boolean_differential(self, injector, crawl_result, param, payload, baseline) -> Optional[DetectionHit]:
        """
        Tests for Boolean SQLi by comparing a TRUE attack vs a FALSE attack.
        If TRUE matches baseline and FALSE deviates significantly, we have a hit.
        """
        from core.scanner.injector import InjectionRequest, PayloadEncoding
        
        # Prepare FALSE payload (e.g. 1=1 -> 1=2)
        false_value = payload.value.replace("1=1", "1=2").replace("'1'='1'", "'1'='2'")
        if false_value == payload.value:
            return None # Cannot construct false condition automatically

        # Run TRUE injection (the original payload)
        true_hit = await self._test_payload(injector, crawl_result, param, payload, baseline)
        if not true_hit:
            return None

        # Run FALSE injection
        false_req = InjectionRequest(
            url=crawl_result.url,
            method=crawl_result.method,
            parameter_name=param.name,
            parameter_location=param.location,
            original_value=param.value,
            payload=false_value,
            encoding=PayloadEncoding.PLAIN,
        )
        
        try:
            false_resp = await injector.inject(false_req)
            if not false_resp.success:
                return None
            
            # Compare response lengths
            # A hit is confirmed if TRUE response length is within 5% of baseline 
            # and FALSE response length is >10% different from TRUE response.
            true_len = len(true_hit.response_body)
            false_len = len(false_resp.body)
            baseline_len = baseline[1]
            
            if abs(true_len - baseline_len) / (baseline_len or 1) < 0.05:
                # TRUE matches normal operation
                diff = abs(true_len - false_len) / (true_len or 1)
                if diff > 0.10:
                    true_hit.matched_text = f"Boolean Differential: TRUE length={true_len}, FALSE length={false_len} (Diff: {diff:.1%})"
                    true_hit.confidence += 0.2
                    return true_hit
        except Exception:
            pass
            
        return None

    def _build_ea_context(self, target, crawl_result, payload: Payload) -> dict:
        return {"ea_relevant": False}