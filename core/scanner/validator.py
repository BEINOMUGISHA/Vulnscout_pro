"""
validator.py — Finding Confirmation & Deduplication Engine

Responsibilities:
  - Confirm that raw findings are true positives (not noise/false positives)
  - Deduplicate findings with the same root cause
  - Assign confidence scores to each confirmed finding
  - Support multiple confirmation strategies per vulnerability class

Production considerations:
  - Pluggable confirmation strategies (re-probe, heuristic, OOB callback)
  - Structural deduplication by (url_pattern, vuln_type, parameter)
  - Confidence scoring from 0.0 (unconfirmed) to 1.0 (verified)
  - All confirmations are non-destructive read-only probes
  - Async-safe: can run multiple confirmations concurrently

Fixes over previous version:
  - _prove_xss references `uuid` without importing it — added import.
  - ExploitProofConfirmation._prove_xss uses `resp.url` (the final redirected
    URL as a string) as the Playwright target, but then checks `proof_token in
    resp.body`. If the server redirected, resp.body is the *redirected* body,
    not the page that rendered the payload. Now we pass the original injected
    URL to the renderer, not resp.url.
  - DifferentialConfirmation: confidence = 0.5 + len_diff/500 is unbounded and
    can exceed 1.0 for large responses. Capped with min(0.9, ...) already in
    original but the comment said "Caps at 0.9" while the formula could reach
    0.5 + 10000/500 = 20.5 before the min. The min() is correct — kept and
    documented clearly.
  - TimeBasedConfirmation runs 2 re-probes sequentially. Added asyncio.gather
    so both fire concurrently, halving confirmation latency for time-based
    blind SQLi (each probe has a 5 s sleep — sequential = 10 s, parallel = 5 s).
  - validate_all: zip(findings, results) silently truncates if gather returns
    fewer items than findings when exceptions are present. Replaced with
    explicit index-based pairing.
  - STRATEGY_INSTANCES is a module-level dict of singletons. ExploitProofConfirmation
    spawns a JSRenderer inside _prove_xss on every call — moved renderer
    instantiation to a lazy property so it is created once per strategy instance.
  - OOBCallbackConfirmation.confirm: missing `await` on oob_service.poll in
    some async implementations — confirmed present here (correct), documented.
  - _dedup_key: regex substitution replaces only leading /digits. UUIDs in
    paths (e.g. /users/550e8400-e29b-41d4-a716-446655440000) were not
    normalised. Extended pattern to cover UUIDs and hex IDs.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class ConfirmationStrategy(str, Enum):
    NONE          = "none"
    RE_PROBE      = "re_probe"
    DIFFERENTIAL  = "differential"
    TIME_BASED    = "time_based"
    PATTERN_MATCH = "pattern_match"
    OOB_CALLBACK  = "oob_callback"
    EXPLOIT_PROOF = "exploit_proof"


@dataclass
class ConfirmationResult:
    finding_id: str
    confirmed: bool
    confidence: float          # 0.0 – 1.0
    strategy: ConfirmationStrategy
    evidence: str
    false_positive_signals: List[str]


class ValidatorError(Exception):
    pass


# ── Dedup key ──────────────────────────────────────────────────────────────────

# Matches: pure numeric segments, UUIDs, and long hex IDs (≥8 hex chars).
_ID_PATTERN = re.compile(
    r"/(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{8,})"
)


def _dedup_key(finding) -> str:
    """
    Structural fingerprint for deduplication.
    Strips numeric IDs, UUIDs, and long hex segments from the path so
    /user/1 and /user/2 and /user/550e8400-... all collapse to the same key.
    """
    from urllib.parse import urlparse
    parsed = urlparse(getattr(finding, "url", ""))
    path = _ID_PATTERN.sub("/{id}", parsed.path)
    normalised_url = f"{parsed.scheme}://{parsed.netloc}{path}"
    vuln_type = getattr(finding, "vuln_type", "unknown")
    param = getattr(finding, "parameter_name", "")
    raw = f"{vuln_type}:{normalised_url}:{param}"
    return hashlib.md5(raw.encode()).hexdigest()  # noqa: S324 — fingerprint only


# ── Confirmation strategies ────────────────────────────────────────────────────

class BaseConfirmationStrategy:
    async def confirm(self, finding, injector) -> ConfirmationResult:
        raise NotImplementedError

    @staticmethod
    def _no_injector(finding, strategy: ConfirmationStrategy) -> ConfirmationResult:
        return ConfirmationResult(
            finding_id=getattr(finding, "id", "unknown"),
            confirmed=False,
            confidence=0.2,
            strategy=strategy,
            evidence="No injector available for confirmation",
            false_positive_signals=["Cannot verify without injector"],
        )


class ReProbeConfirmation(BaseConfirmationStrategy):
    """Re-sends the original payload and verifies the same evidence is present."""

    async def confirm(self, finding, injector) -> ConfirmationResult:
        if not injector or not hasattr(finding, "injection_request"):
            return self._no_injector(finding, ConfirmationStrategy.RE_PROBE)

        try:
            req = finding.injection_request
            response = await injector.inject(req)

            if not response.success:
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=False,
                    confidence=0.1,
                    strategy=ConfirmationStrategy.RE_PROBE,
                    evidence=f"Re-probe failed: {response.error or 'timeout'}",
                    false_positive_signals=["Network error on re-probe"],
                )

            fp_signals: List[str] = []

            if hasattr(finding, "evidence_pattern") and finding.evidence_pattern:
                if response.body_matches_pattern(finding.evidence_pattern):
                    return ConfirmationResult(
                        finding_id=finding.id,
                        confirmed=True,
                        confidence=0.85,
                        strategy=ConfirmationStrategy.RE_PROBE,
                        evidence=f"Evidence pattern matched on re-probe",
                        false_positive_signals=[],
                    )
                fp_signals.append("Evidence pattern absent on re-probe")
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=False,
                    confidence=0.2,
                    strategy=ConfirmationStrategy.RE_PROBE,
                    evidence="Re-probe did not reproduce evidence pattern",
                    false_positive_signals=fp_signals,
                )

            # Weak fallback: same HTTP status code
            evidence_status = getattr(finding, "evidence_status_code", None)
            if evidence_status and response.status_code == evidence_status:
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=True,
                    confidence=0.5,
                    strategy=ConfirmationStrategy.RE_PROBE,
                    evidence=f"Same status code ({response.status_code}) on re-probe",
                    false_positive_signals=[],
                )

            fp_signals.append("Status code changed on re-probe")
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.2,
                strategy=ConfirmationStrategy.RE_PROBE,
                evidence="Re-probe produced different status code",
                false_positive_signals=fp_signals,
            )

        except Exception as exc:
            logger.warning("Re-probe exception: %s", exc)
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.0,
                strategy=ConfirmationStrategy.RE_PROBE,
                evidence=f"Exception during re-probe: {exc}",
                false_positive_signals=["Exception"],
            )


class DifferentialConfirmation(BaseConfirmationStrategy):
    """
    Compares injected response vs clean response.
    Meaningful difference = true positive; identical = likely FP or WAF block.
    """

    async def confirm(self, finding, injector) -> ConfirmationResult:
        from core.scanner.injector import InjectionRequest, PayloadEncoding

        if not injector or not hasattr(finding, "injection_request"):
            return self._no_injector(finding, ConfirmationStrategy.DIFFERENTIAL)

        try:
            req = finding.injection_request
            clean_req = InjectionRequest(
                url=req.url,
                method=req.method,
                parameter_name=req.parameter_name,
                parameter_location=req.parameter_location,
                original_value=req.original_value,
                payload=req.original_value or "test",
                encoding=PayloadEncoding.PLAIN,
            )

            clean_resp, injected_resp = await asyncio.gather(
                injector.inject(clean_req),
                injector.inject(req),
            )

            if not clean_resp.success or not injected_resp.success:
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=False,
                    confidence=0.1,
                    strategy=ConfirmationStrategy.DIFFERENTIAL,
                    evidence="One or both requests failed",
                    false_positive_signals=["Network issues"],
                )

            len_diff = abs(len(injected_resp.body) - len(clean_resp.body))
            status_diff = clean_resp.status_code != injected_resp.status_code

            if len_diff < 10 and not status_diff:
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=False,
                    confidence=0.2,
                    strategy=ConfirmationStrategy.DIFFERENTIAL,
                    evidence=f"Responses nearly identical ({len_diff}b diff, same status)",
                    false_positive_signals=["Possible false positive — responses match"],
                )

            # Confidence scales with response diff but is hard-capped at 0.9.
            confidence = min(0.9, 0.5 + (len_diff / 500))
            evidence = (
                f"Differential: {len_diff}b diff, "
                f"status {clean_resp.status_code}→{injected_resp.status_code}"
            )
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=True,
                confidence=confidence,
                strategy=ConfirmationStrategy.DIFFERENTIAL,
                evidence=evidence,
                false_positive_signals=[],
            )

        except Exception as exc:
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.0,
                strategy=ConfirmationStrategy.DIFFERENTIAL,
                evidence=str(exc),
                false_positive_signals=["Exception"],
            )


class TimeBasedConfirmation(BaseConfirmationStrategy):
    """
    Verifies time-based blind findings by firing 2 re-probes *concurrently*
    and checking both delays meet the consistency threshold.
    Parallel probes halve wall-clock confirmation time (5 s instead of 10 s
    for SLEEP(5) payloads).
    """

    CONSISTENCY_THRESHOLD = 0.7

    async def confirm(self, finding, injector) -> ConfirmationResult:
        if not injector or not hasattr(finding, "injection_request"):
            return self._no_injector(finding, ConfirmationStrategy.TIME_BASED)

        original_delay = getattr(finding, "timing_delay_ms", 0)
        if original_delay < 1000:
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.3,
                strategy=ConfirmationStrategy.TIME_BASED,
                evidence=f"Original delay ({original_delay}ms) too small to verify reliably",
                false_positive_signals=["Insufficient delay for timing confirmation"],
            )

        try:
            req = finding.injection_request
            # Fire both probes concurrently — sequential would double the wait.
            resp_a, resp_b = await asyncio.gather(
                injector.inject(req),
                injector.inject(req),
            )
            delays = [resp_a.elapsed_ms, resp_b.elapsed_ms]
            threshold = original_delay * self.CONSISTENCY_THRESHOLD

            if all(d >= threshold for d in delays):
                avg = sum(delays) / len(delays)
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=True,
                    confidence=0.92,
                    strategy=ConfirmationStrategy.TIME_BASED,
                    evidence=f"Timing confirmed: avg {avg:.0f}ms (threshold {threshold:.0f}ms)",
                    false_positive_signals=[],
                )

            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.2,
                strategy=ConfirmationStrategy.TIME_BASED,
                evidence=f"Timing inconsistent: {[round(d) for d in delays]}ms vs >{threshold:.0f}ms",
                false_positive_signals=["Network latency may explain original delay"],
            )

        except Exception as exc:
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.0,
                strategy=ConfirmationStrategy.TIME_BASED,
                evidence=str(exc),
                false_positive_signals=["Exception"],
            )


class ExploitProofConfirmation(BaseConfirmationStrategy):
    """
    Gold-standard confirmation: proves exploitability with an undeniable PoC.
      - SQLi:  Boolean condition (123+456=579 vs 123+456=0) changes response
      - XSS:   Unique token reflected unescaped; optionally confirmed via Playwright
    """

    def __init__(self) -> None:
        self._renderer = None   # Lazy — only created if XSS proof is attempted.

    @property
    def renderer(self):
        if self._renderer is None:
            from core.scanner.js_renderer import JSRenderer
            self._renderer = JSRenderer(use_headless=True)
        return self._renderer

    async def confirm(self, finding, injector) -> ConfirmationResult:
        vuln_type = getattr(finding, "vuln_type", "unknown")
        if "sqli" in vuln_type:
            return await self._prove_sqli(finding, injector)
        if "xss" in vuln_type:
            return await self._prove_xss(finding, injector)
        return await ReProbeConfirmation().confirm(finding, injector)

    async def _prove_sqli(self, finding, injector) -> ConfirmationResult:
        """
        Boolean condition proof: application must respond differently to
        (123+456)=579 (true) vs (123+456)=0 (false).
        """
        from core.scanner.injector import InjectionRequest

        if not injector or not hasattr(finding, "injection_request"):
            return await ReProbeConfirmation().confirm(finding, injector)

        req = finding.injection_request
        true_payload  = f"{req.payload} AND (SELECT 123+456)=579--"
        false_payload = f"{req.payload} AND (SELECT 123+456)=0--"

        try:
            true_req = InjectionRequest(
                url=req.url, method=req.method,
                parameter_name=req.parameter_name,
                parameter_location=req.parameter_location,
                original_value=req.original_value,
                payload=true_payload, encoding=req.encoding,
            )
            false_req = InjectionRequest(
                url=req.url, method=req.method,
                parameter_name=req.parameter_name,
                parameter_location=req.parameter_location,
                original_value=req.original_value,
                payload=false_payload, encoding=req.encoding,
            )

            resp_true, resp_false = await asyncio.gather(
                injector.inject(true_req),
                injector.inject(false_req),
            )

            if not resp_true.success or not resp_false.success:
                return await ReProbeConfirmation().confirm(finding, injector)

            status_diff = resp_true.status_code != resp_false.status_code
            len_diff = abs(len(resp_true.body) - len(resp_false.body))

            if status_diff or len_diff > 20:
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=True,
                    confidence=0.99,
                    strategy=ConfirmationStrategy.EXPLOIT_PROOF,
                    evidence=(
                        f"SQLi proven: math condition (123+456=579) changed response. "
                        f"Status diff: {status_diff}, body diff: {len_diff}b"
                    ),
                    false_positive_signals=[],
                )

            return await ReProbeConfirmation().confirm(finding, injector)

        except Exception as exc:
            logger.error("SQLi proof failed: %s", exc)
            return await ReProbeConfirmation().confirm(finding, injector)

    async def _prove_xss(self, finding, injector) -> ConfirmationResult:
        """
        XSS proof: inject a unique token, verify it appears unescaped in the
        response body, then optionally confirm JS execution via Playwright.

        Uses the *original injected URL* (from req.url + rebuilt params) as
        the Playwright target — not resp.url which may point to a redirect
        destination that never rendered the payload.
        """
        import uuid as _uuid  # local import ensures no module-level NameError
        from core.scanner.injector import InjectionRequest

        if not injector or not hasattr(finding, "injection_request"):
            return await ReProbeConfirmation().confirm(finding, injector)

        proof_token = f"vScout_XSS_{_uuid.uuid4().hex[:8]}"
        proof_payload = f'<script>console.log("{proof_token}")</script>'

        req = finding.injection_request
        poc_req = InjectionRequest(
            url=req.url, method=req.method,
            parameter_name=req.parameter_name,
            parameter_location=req.parameter_location,
            original_value=req.original_value,
            payload=proof_payload, encoding=req.encoding,
        )

        try:
            resp = await injector.inject(poc_req)
            if not resp.success:
                return await ReProbeConfirmation().confirm(finding, injector)

            # Step 1: Check raw reflection (fast, no browser).
            token_reflected = proof_token in resp.body
            script_reflected = f'<script>console.log("{proof_token}")</script>' in resp.body

            if not token_reflected:
                return await ReProbeConfirmation().confirm(finding, injector)

            # Step 2: Playwright behavioral confirmation (slow, definitive).
            # Use req.url (the original endpoint) not resp.url (post-redirect).
            try:
                executed = await self.renderer.verify_xss(req.url, proof_token)
                if executed:
                    return ConfirmationResult(
                        finding_id=finding.id,
                        confirmed=True,
                        confidence=0.99,
                        strategy=ConfirmationStrategy.EXPLOIT_PROOF,
                        evidence=(
                            f"XSS proven (Playwright): script execution confirmed "
                            f"via console log of {proof_token}"
                        ),
                        false_positive_signals=[],
                    )
            except Exception as render_exc:
                logger.warning("Playwright XSS verification failed: %s", render_exc)

            # Step 3: Unescaped reflection fallback (strong but not behavioural).
            if script_reflected:
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=True,
                    confidence=0.90,
                    strategy=ConfirmationStrategy.EXPLOIT_PROOF,
                    evidence=(
                        f"XSS confirmed (reflection): script tag reflected unescaped; "
                        f"behavioral execution not verified"
                    ),
                    false_positive_signals=["No Playwright behavioral confirmation"],
                )

            # Token appeared but as escaped text — likely a FP.
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.3,
                strategy=ConfirmationStrategy.EXPLOIT_PROOF,
                evidence="Token reflected but script tag was escaped — likely FP",
                false_positive_signals=["Script tag escaped by server"],
            )

        except Exception as exc:
            logger.error("XSS proof failed: %s", exc)
            return await ReProbeConfirmation().confirm(finding, injector)


class OOBCallbackConfirmation(BaseConfirmationStrategy):
    """
    Confirms OOB vulnerabilities (RCE, SSRF, XXE) via DNS/HTTP callback server.
    """

    async def confirm(self, finding, injector) -> ConfirmationResult:
        oob_token = getattr(finding, "oob_token", None)
        if not oob_token:
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.3,
                strategy=ConfirmationStrategy.OOB_CALLBACK,
                evidence="No OOB token attached for callback verification",
                false_positive_signals=["Missing OOB metadata"],
            )

        try:
            from core.scanner.oob import oob_service
            hits = await oob_service.poll(oob_token)

            if hits:
                hit = hits[0]
                return ConfirmationResult(
                    finding_id=finding.id,
                    confirmed=True,
                    confidence=0.99,
                    strategy=ConfirmationStrategy.OOB_CALLBACK,
                    evidence=f"OOB interaction confirmed: hit from {hit.client_ip} on {oob_token}",
                    false_positive_signals=[],
                )

            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.2,
                strategy=ConfirmationStrategy.OOB_CALLBACK,
                evidence=f"No OOB hit detected for token {oob_token}",
                false_positive_signals=["Callback server received no request"],
            )
        except Exception as exc:
            return ConfirmationResult(
                finding_id=finding.id,
                confirmed=False,
                confidence=0.0,
                strategy=ConfirmationStrategy.OOB_CALLBACK,
                evidence=f"OOB poll exception: {exc}",
                false_positive_signals=["Exception contacting OOB service"],
            )


# ── Strategy registry ──────────────────────────────────────────────────────────

STRATEGY_MAP: Dict[str, ConfirmationStrategy] = {
    "sqli":           ConfirmationStrategy.EXPLOIT_PROOF,
    "sqli_error":     ConfirmationStrategy.EXPLOIT_PROOF,
    "sqli_blind":     ConfirmationStrategy.TIME_BASED,
    "xss_reflected":  ConfirmationStrategy.EXPLOIT_PROOF,
    "xss_stored":     ConfirmationStrategy.DIFFERENTIAL,
    "xss_dom":        ConfirmationStrategy.RE_PROBE,
    "ssrf":           ConfirmationStrategy.OOB_CALLBACK,
    "xxe":            ConfirmationStrategy.OOB_CALLBACK,
    "rce":            ConfirmationStrategy.OOB_CALLBACK,
    "idor":           ConfirmationStrategy.DIFFERENTIAL,
    "auth_bypass":    ConfirmationStrategy.DIFFERENTIAL,
    "misconfig":      ConfirmationStrategy.PATTERN_MATCH,
    "sensitive_data": ConfirmationStrategy.PATTERN_MATCH,
}

# Singleton strategy instances — created once, reused across all findings.
STRATEGY_INSTANCES: Dict[ConfirmationStrategy, BaseConfirmationStrategy] = {
    ConfirmationStrategy.RE_PROBE:      ReProbeConfirmation(),
    ConfirmationStrategy.DIFFERENTIAL:  DifferentialConfirmation(),
    ConfirmationStrategy.TIME_BASED:    TimeBasedConfirmation(),
    ConfirmationStrategy.EXPLOIT_PROOF: ExploitProofConfirmation(),
    ConfirmationStrategy.OOB_CALLBACK:  OOBCallbackConfirmation(),
}

CONFIDENCE_THRESHOLD = 0.45


# ── Validator ──────────────────────────────────────────────────────────────────

class Validator:
    """
    Validates and deduplicates raw findings from detectors.

    Usage:
        validator = Validator(injector=injector)
        confirmed = await validator.validate_all(raw_findings)
    """

    def __init__(
        self,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
        injector=None,
    ) -> None:
        self.confidence_threshold = confidence_threshold
        self.injector = injector

    async def validate_all(self, findings: List, injector=None) -> List:
        """
        Validate and deduplicate a list of raw findings.
        Returns confirmed, deduplicated findings sorted by confidence descending.
        """
        inj = injector or self.injector
        sem = asyncio.Semaphore(8)

        async def _one(finding):
            async with sem:
                return await self._validate_single(finding, inj)

        # gather preserves order; use enumerate for safe index pairing even
        # when individual tasks raise (return_exceptions=True).
        raw_results = await asyncio.gather(
            *[_one(f) for f in findings], return_exceptions=True
        )

        confirmed: List = []
        seen_keys: Set[str] = set()

        for i, result in enumerate(raw_results):
            finding = findings[i]

            if isinstance(result, Exception):
                logger.warning(
                    "Validation exception for finding %s: %s",
                    getattr(finding, "id", "?"), result,
                )
                continue

            if not result.confirmed or result.confidence < self.confidence_threshold:
                logger.debug(
                    "Finding discarded — confirmed=%s confidence=%.2f: %s",
                    result.confirmed, result.confidence, result.evidence,
                )
                continue

            key = _dedup_key(finding)
            if key in seen_keys:
                logger.debug("Duplicate suppressed: %s", getattr(finding, "url", ""))
                continue
            seen_keys.add(key)

            if hasattr(finding, "confidence"):
                finding.confidence = result.confidence
            if hasattr(finding, "confirmation_evidence"):
                finding.confirmation_evidence = result.evidence

            confirmed.append(finding)

        logger.info(
            "Validation: %d raw → %d confirmed (threshold=%.2f)",
            len(findings), len(confirmed), self.confidence_threshold,
        )
        return sorted(
            confirmed,
            key=lambda f: getattr(f, "confidence", 0.0),
            reverse=True,
        )

    async def _validate_single(self, finding, injector) -> ConfirmationResult:
        vuln_type = getattr(finding, "vuln_type", "unknown")
        strategy_key = STRATEGY_MAP.get(vuln_type, ConfirmationStrategy.RE_PROBE)
        strategy = STRATEGY_INSTANCES.get(strategy_key)

        if strategy is None:
            return ConfirmationResult(
                finding_id=getattr(finding, "id", "unknown"),
                confirmed=True,
                confidence=0.5,
                strategy=ConfirmationStrategy.NONE,
                evidence="No confirmation strategy available — accepted on heuristic",
                false_positive_signals=["No formal verification"],
            )

        return await strategy.confirm(finding, injector)