"""
base_detector.py — Abstract Base Detector

Every detection module inherits from BaseDetector. This enforces a
consistent interface across all 9 detectors and provides shared utilities:

  - Structured Finding construction
  - Payload → response → evidence pipeline helpers
  - EA context enrichment hook
  - Confidence scoring helpers
  - Safe regex matching (never crashes the scan)
  - Timing measurement utilities for blind detection

Detector contract:
  1. detect(target, crawl_result, injector) → List[Finding]
  2. Each Finding has: url, parameter_name, vuln_type, cvss_vector,
     evidence (InjectionRequest + response excerpt), evidence_pattern
  3. Detectors do NOT validate — raw findings go to validator.py
  4. Detectors do NOT score — raw findings get cvss_score=0.0
  5. Detectors MUST respect cancellation (check injector.rate_limiter state)
  6. Detectors MUST be stateless — safe to run concurrently
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

logger = logging.getLogger(__name__)


# ── Detector metadata ──────────────────────────────────────────────────────────

@dataclass
class DetectorMeta:
    """Static metadata about a detector — read by the registry."""
    detector_id: str          # e.g. "sqli", "xss_reflected"
    name: str                 # Human-readable name
    description: str
    vuln_types: List[str]     # VulnType values this detector can produce
    owasp_categories: List[str]
    default_enabled: bool = True
    ea_specific: bool = False   # True for EA-only detectors
    requires_auth: bool = False
    estimated_requests_per_endpoint: int = 10


# ── Payload definition ─────────────────────────────────────────────────────────

@dataclass
class Payload:
    """A single test payload with metadata."""
    value: str
    description: str
    evidence_pattern: str          # Regex to detect in response
    false_positive_pattern: str = ""
    vuln_type: str = ""
    cvss_vector: str = ""
    confidence_boost: float = 0.0  # Added to base confidence on match
    is_blind: bool = False         # Time-based or OOB — no inline evidence
    delay_seconds: float = 0.0     # Expected delay for time-based payloads

    def compile_evidence(self) -> Optional[Pattern]:
        if not self.evidence_pattern:
            return None
        try:
            return re.compile(self.evidence_pattern, re.IGNORECASE | re.DOTALL)
        except re.error:
            logger.warning("Invalid evidence pattern: %s", self.evidence_pattern)
            return None

    def compile_false_positive(self) -> Optional[Pattern]:
        if not self.false_positive_pattern:
            return None
        try:
            return re.compile(self.false_positive_pattern, re.IGNORECASE)
        except re.error:
            return None


# ── Detection result (pre-Finding) ────────────────────────────────────────────

@dataclass
class DetectionHit:
    """
    Intermediate result from a single payload test.
    Converted to a Finding by _build_finding().
    """
    url: str
    method: str
    parameter_name: str
    parameter_location: str
    payload: Payload
    response_status: int
    response_body: str
    response_headers: Dict[str, str]
    elapsed_ms: float
    matched_text: str = ""
    injection_request: object = None   # InjectionRequest
    confidence: float = 0.5


# ── Base detector ──────────────────────────────────────────────────────────────

class BaseDetector(ABC):
    """
    Abstract base for all VulnScout Pro detection modules.

    Subclasses must implement:
      - meta: DetectorMeta property
      - payloads: List[Payload] property
      - detect(): main detection coroutine

    Subclasses may override:
      - _should_test_parameter(): skip irrelevant params
      - _pre_detect(): setup before payload loop
      - _post_detect(): cleanup / extra checks after payload loop
    """

    def __init__(self) -> None:
        self._compiled_evidence: Dict[str, Optional[Pattern]] = {}
        self._compiled_fp: Dict[str, Optional[Pattern]] = {}

    # ── Abstract interface ─────────────────────────────────────────────────────

    @property
    @abstractmethod
    def meta(self) -> DetectorMeta:
        """Static metadata about this detector."""

    @property
    @abstractmethod
    def payloads(self) -> List[Payload]:
        """Ordered list of payloads to test."""

    @abstractmethod
    async def detect(
        self,
        target,          # Target
        crawl_result,    # CrawlResult
        injector,        # Injector
    ) -> List:           # List[Finding]
        """
        Run detection against a single crawled endpoint.
        Must be async, stateless, and safe to call concurrently.
        """

    # ── Shared helpers ─────────────────────────────────────────────────────────

    async def _get_baseline(
        self,
        injector,
        crawl_result,
        param,
    ) -> Tuple[float, int]:
        """
        Measure the average response time (ms) and body length for a parameter.
        Uses 2 requests to average out jitter.
        """
        from core.scanner.injector import InjectionRequest, PayloadEncoding
        
        req = InjectionRequest(
            url=crawl_result.url,
            method=crawl_result.method,
            parameter_name=param.name,
            parameter_location=param.location,
            original_value=param.value,
            payload=param.value or "", # Use original value as baseline
            encoding=PayloadEncoding.PLAIN,
        )

        times = []
        lengths = []
        
        logger.debug("[baseline] Starting baseline for %s (param: %s)", crawl_result.url, param.name)
        for i in range(2):
            start = time.monotonic()
            try:
                resp = await injector.inject(req)
                if resp.success:
                    times.append((time.monotonic() - start) * 1000)
                    lengths.append(len(resp.body))
                    logger.debug("[baseline] Request %d success: %d bytes, %.1fms", i+1, len(resp.body), times[-1])
                else:
                    logger.warning("[baseline] Request %d FAILED (status: %d, error: %s)", i+1, resp.status_code, resp.error)
            except Exception as e:
                logger.error("[baseline] Request %d CRASHED: %s", i+1, e)
                continue
                
        if not times:
            logger.warning("[baseline] Complete failure for %s. Using fallback baseline (200ms, 0 bytes)", param.name)
            return 200.0, 0 # Fallback
            
        avg_time = sum(times) / len(times)
        avg_len = int(sum(lengths) / len(lengths))
        logger.info("[baseline] Baseline established for %s: avg_ms=%.1f, avg_len=%d", param.name, avg_time, avg_len)
        return avg_time, avg_len

    async def _test_payload(
        self,
        injector,
        crawl_result,
        param,            # CrawlParameter
        payload: Payload,
        baseline: Optional[Tuple[float, int]] = None,
    ) -> Optional[DetectionHit]:
        """
        Send one payload to one parameter and return a DetectionHit if matched.
        Returns None on network error or no match.
        """
        from core.scanner.injector import InjectionRequest, PayloadEncoding

        req = InjectionRequest(
            url=crawl_result.url,
            method=crawl_result.method,
            parameter_name=param.name,
            parameter_location=param.location,
            original_value=param.value,
            payload=payload.value,
            encoding=PayloadEncoding.PLAIN,
        )

        start = time.monotonic()
        try:
            resp = await injector.inject(req)
            if not resp.success:
                logger.debug("[test_payload] Request failed for %s (param: %s, payload: %s): status=%d error=%s", 
                             self.meta.detector_id, param.name, payload.value[:20], resp.status_code, resp.error)
                return None
        except Exception as exc:
            logger.error("[test_payload] CRASH in %s: %s", self.meta.detector_id, exc)
            return None

        elapsed_ms = (time.monotonic() - start) * 1000

        # Check for match
        matched, matched_text = self._check_evidence(payload, resp.body, elapsed_ms, baseline)
        if not matched:
            return None

        logger.info("[hit] %s DETECTED! URL: %s Param: %s Payload: %s", 
                    self.meta.detector_id, crawl_result.url, param.name, payload.value[:30])

        return DetectionHit(
            url=crawl_result.url,
            method=crawl_result.method,
            parameter_name=param.name,
            parameter_location=param.location,
            payload=payload,
            response_status=resp.status_code,
            response_body=resp.body,
            response_headers=resp.response_headers,
            elapsed_ms=elapsed_ms,
            matched_text=matched_text,
            injection_request=req,
            confidence=0.5 + payload.confidence_boost,
        )

    def _check_evidence(
        self,
        payload: Payload,
        body: str,
        elapsed_ms: float,
        baseline: Optional[Tuple[float, int]] = None,
    ) -> Tuple[bool, str]:
        """
        Check if a response body matches a payload's evidence pattern.
        Returns (matched, matched_text).
        Handles time-based payloads specially.
        """
        # Time-based blind detection
        if payload.is_blind and payload.delay_seconds > 0:
            baseline_ms = baseline[0] if baseline else 200.0
            expected_total_ms = baseline_ms + (payload.delay_seconds * 1000)
            
            # Significant delay is baseline + 80% of sleep time
            if elapsed_ms >= baseline_ms + (payload.delay_seconds * 1000 * 0.8):
                return True, f"Response delayed {elapsed_ms:.0f}ms (Baseline: {baseline_ms:.0f}ms, Expected: >{expected_total_ms:.0f}ms)"
            return False, ""

        # Pattern-based detection
        if not payload.evidence_pattern:
            # If no pattern and not blind, we treat it as a match (e.g. for differential testing)
            return True, "Pattern-less match (for differential analysis)"

        pattern = self._get_compiled_evidence(payload)
        if pattern is None:
            return False, ""

        match = pattern.search(body)
        if not match:
            return False, ""

        # Check false positive suppression
        fp_pattern = self._get_compiled_fp(payload)
        if fp_pattern and fp_pattern.search(body):
            logger.debug(
                "False positive suppressed for payload '%s'", payload.value[:40]
            )
            return False, ""

        return True, match.group(0)[:200]

    def _get_compiled_evidence(self, payload: Payload) -> Optional[Pattern]:
        key = payload.evidence_pattern
        if key not in self._compiled_evidence:
            self._compiled_evidence[key] = payload.compile_evidence()
        return self._compiled_evidence[key]

    def _get_compiled_fp(self, payload: Payload) -> Optional[Pattern]:
        key = payload.false_positive_pattern
        if key not in self._compiled_fp:
            self._compiled_fp[key] = payload.compile_false_positive()
        return self._compiled_fp[key]

    def _build_finding(
        self,
        hit: DetectionHit,
        scan_id: str = "",
        ea_context: Optional[Dict] = None,
    ):
        """
        Convert a DetectionHit into a Finding object.
        Attaches evidence and EA context.
        """
        from core.models.finding import Finding, FindingEvidence, EAContext

        evidence = FindingEvidence(
            request_method=hit.method,
            request_url=hit.url,
            injected_parameter=hit.parameter_name,
            injected_payload=hit.payload.value,
            response_status=hit.response_status,
            response_body_excerpt=self._safe_excerpt(hit.response_body, hit.matched_text),
            matched_pattern=hit.payload.evidence_pattern,
            timing_delta_ms=hit.elapsed_ms,
        )

        ea = EAContext()
        if ea_context:
            ea = EAContext(**{
                k: v for k, v in ea_context.items()
                if k in EAContext.__dataclass_fields__
            })

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            url=hit.url,
            parameter_name=hit.parameter_name,
            parameter_location=hit.parameter_location,
            vuln_type=hit.payload.vuln_type or self.meta.vuln_types[0],
            cvss_vector=hit.payload.cvss_vector,
            confidence=hit.confidence,
            evidence=evidence,
            evidence_pattern=hit.payload.evidence_pattern,
            evidence_status_code=hit.response_status,
            timing_delay_ms=hit.elapsed_ms if hit.payload.is_blind else 0.0,
            injection_request=hit.injection_request,
            ea_context=ea,
        )
        return finding

    def _should_test_parameter(self, param, crawl_result) -> bool:
        """
        Override to skip irrelevant parameters.
        Default: skip static file extensions.
        """
        static_ext = re.compile(
            r"\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|pdf)$",
            re.IGNORECASE,
        )
        if static_ext.search(crawl_result.url):
            return False
        return True

    @staticmethod
    def _safe_excerpt(body: str, matched_text: str, context: int = 200) -> str:
        """Extract a context window around the matched text."""
        if not body:
            return ""
        if not matched_text:
            return body[:500]
        idx = body.lower().find(matched_text.lower())
        if idx == -1:
            # If not found in body, it might be a synthetic message (e.g. "Response delayed")
            return matched_text
        start = max(0, idx - context)
        end = min(len(body), idx + len(matched_text) + context)
        return body[start:end]

    @staticmethod
    def _log_hit(detector_id: str, url: str, param: str, payload_desc: str) -> None:
        logger.info(
            "[%s] HIT url=%s param=%s payload=%s",
            detector_id, url, param, payload_desc[:60],
        )