"""
false_positive.py — False Positive Suppression Engine

Reduces noise in scan results by identifying and suppressing findings
that are almost certainly false positives before they reach the report.

Three suppression layers:

  Layer 1 — Structural filters
    Hard rules that apply regardless of response content. If a finding
    matches a structural rule it is suppressed with high confidence.
    Examples: error-based SQLi on a 404 page, XSS in a JSON API response
    that HTML-escapes by definition, time-based SQLi with sub-threshold delay.

  Layer 2 — Response analysis
    Examines the injection response for patterns that indicate a WAF,
    sanitisation layer, or framework-level escaping intercepted the payload
    before it reached the vulnerable component.

  Layer 3 — Differential analysis
    Compares the injected response to a clean baseline. If the responses
    are structurally identical, the payload had no effect and the match
    was coincidental.

  Layer 4 — EA-specific false positive patterns
    Patterns specific to common EA stacks: CodeIgniter's default error pages
    contain SQL-looking text; some Ugandan ISP error pages mirror payloads
    back in their "page not found" messages; Laravel's debug page contains
    stack traces that look like injection evidence.

Output:
  FPResult.is_fp     — True if suppressed
  FPResult.reason    — Why it was suppressed (logged, never shown to user)
  FPResult.confidence — 0.0–1.0 confidence this IS a false positive
"""

from __future__ import annotations

import difflib
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

logger = logging.getLogger(__name__)


# ── FP result ──────────────────────────────────────────────────────────────────

@dataclass
class FPResult:
    """Result of a false positive check for one finding."""
    is_fp: bool
    reason: str
    confidence: float          # 0.0 = definitely real, 1.0 = definitely FP
    layer: str = ""            # Which layer caught it
    suppressed_pattern: str = ""

    @classmethod
    def clean(cls) -> "FPResult":
        return cls(is_fp=False, reason="", confidence=0.0)

    @classmethod
    def suppressed(
        cls, reason: str, confidence: float, layer: str, pattern: str = ""
    ) -> "FPResult":
        return cls(
            is_fp=True,
            reason=reason,
            confidence=confidence,
            layer=layer,
            suppressed_pattern=pattern,
        )


# ── Layer 1 — Structural rules ─────────────────────────────────────────────────

@dataclass
class StructuralRule:
    """A hard structural rule that marks a finding as FP."""
    rule_id: str
    description: str
    applies_to_vuln_types: List[str]   # Empty = applies to all
    condition: str                      # Description of the condition
    fp_confidence: float = 0.95

    def check(self, finding, response_body: str, status_code: int, elapsed_ms: float) -> Optional[FPResult]:
        raise NotImplementedError


class StatusCode404Rule(StructuralRule):
    """Any finding on a 404 page is almost certainly FP."""
    def check(self, finding, response_body, status_code, elapsed_ms):
        if status_code == 404:
            return FPResult.suppressed(
                "404 response — not a real endpoint",
                confidence=0.97,
                layer="structural",
                pattern="status_code=404",
            )
        return None


class JSONResponseXSSRule(StructuralRule):
    """
    XSS on a JSON API response — JSON encoding prevents script execution.
    The payload may appear in the response but it's serialised inside JSON
    string value, so <, >, " are JSON-escaped.
    """
    _JSON_CONTENT = re.compile(r"application/json", re.IGNORECASE)
    _ESCAPED = re.compile(r"\\u003[Cc]|\\u003[Ee]|&lt;|&gt;|\\x3[Cc]|\\x3[Ee]")

    def check(self, finding, response_body, status_code, elapsed_ms):
        vuln_type = getattr(finding, "vuln_type", "")
        if "xss" not in vuln_type:
            return None
        content_type = getattr(finding, "evidence", None)
        if content_type:
            ct = getattr(finding.evidence, "response_headers", {}).get("Content-Type", "")
            if self._JSON_CONTENT.search(ct):
                if self._ESCAPED.search(response_body):
                    return FPResult.suppressed(
                        "XSS payload JSON-encoded in API response — not executable",
                        confidence=0.92,
                        layer="structural",
                        pattern="json_encoded_xss",
                    )
        return None


class BlindSQLiTimingRule(StructuralRule):
    """
    Time-based blind SQLi with elapsed time below threshold is FP.
    We require ≥ 80% of the expected delay.
    """
    def check(self, finding, response_body, status_code, elapsed_ms):
        vuln_type = getattr(finding, "vuln_type", "")
        if vuln_type != "sqli_blind":
            return None
        expected_ms = getattr(finding, "timing_delay_ms", 5000.0)
        if expected_ms <= 0:
            return None
        if elapsed_ms < expected_ms * 0.75:
            return FPResult.suppressed(
                f"Blind SQLi delay {elapsed_ms:.0f}ms < 75% of expected {expected_ms:.0f}ms",
                confidence=0.90,
                layer="structural",
                pattern="insufficient_timing_delay",
            )
        return None


class RedirectResponseRule(StructuralRule):
    """
    Finding on a 3xx redirect response — payload was never processed.
    """
    def check(self, finding, response_body, status_code, elapsed_ms):
        if 300 <= status_code < 400:
            return FPResult.suppressed(
                f"Redirect response ({status_code}) — payload not processed",
                confidence=0.93,
                layer="structural",
                pattern=f"status_code={status_code}",
            )
        return None


class ErrorPageSQLiRule(StructuralRule):
    """
    SQLi error pattern found on a page that always shows that error,
    regardless of injection (generic application error page).
    """
    _GENERIC_ERROR = re.compile(
        r"(?i)(page not found|404 error|403 forbidden|"
        r"access denied|internal server error|"
        r"service unavailable|bad gateway)",
        re.IGNORECASE,
    )

    def check(self, finding, response_body, status_code, elapsed_ms):
        vuln_type = getattr(finding, "vuln_type", "")
        if "sqli" not in vuln_type:
            return None
        if status_code in (403, 503) and self._GENERIC_ERROR.search(response_body):
            return FPResult.suppressed(
                "SQL error pattern in generic error page — not injectable",
                confidence=0.88,
                layer="structural",
                pattern="generic_error_page",
            )
        return None


STRUCTURAL_RULES: List[StructuralRule] = [
    StatusCode404Rule(
        "SR-001", "404 not found", [], "status_code=404", 0.97
    ),
    RedirectResponseRule(
        "SR-002", "3xx redirect", [], "3xx_redirect", 0.93
    ),
    JSONResponseXSSRule(
        "SR-003", "JSON-encoded XSS", ["xss_reflected"], "json_encoding", 0.92
    ),
    BlindSQLiTimingRule(
        "SR-004", "Insufficient blind SQLi delay", ["sqli_blind"], "timing", 0.90
    ),
    ErrorPageSQLiRule(
        "SR-005", "SQL error in generic error page", ["sqli", "sqli_error"], "generic_error", 0.88
    ),
]


# ── Layer 2 — Response analysis patterns ──────────────────────────────────────

@dataclass
class ResponsePattern:
    """A pattern in the response that indicates sanitisation / WAF interception."""
    pattern_id: str
    name: str
    regex: str
    applies_to_vuln_types: List[str]   # Empty = all
    fp_confidence: float
    description: str
    _compiled: Optional[Pattern] = field(default=None, repr=False)

    def matches(self, body: str) -> bool:
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.regex, re.IGNORECASE | re.DOTALL)
            except re.error:
                return False
        return bool(self._compiled.search(body))


# WAF / sanitisation response patterns
RESPONSE_FP_PATTERNS: List[ResponsePattern] = [

    # ── WAF block pages ────────────────────────────────────────────────────────
    ResponsePattern(
        "RP-001", "Cloudflare WAF block",
        r"(cloudflare|cf-ray|__cf_bm|Attention Required|Cloudflare Ray ID)",
        [],
        0.96,
        "Cloudflare WAF intercepted the request",
    ),
    ResponsePattern(
        "RP-002", "AWS WAF block",
        r"(AWS WAF|Request blocked|403 Forbidden.*AWS)",
        [],
        0.95,
        "AWS WAF intercepted the request",
    ),
    ResponsePattern(
        "RP-003", "ModSecurity block",
        r"(ModSecurity|mod_security|NAXSI|Not Acceptable.*security)",
        [],
        0.94,
        "ModSecurity/NAXSI WAF intercepted the request",
    ),
    ResponsePattern(
        "RP-004", "Generic WAF/IPS block",
        r"(your request has been blocked|security policy|"
        r"attack detected|malicious request|"
        r"suspicious activity|request rejected.*security)",
        [],
        0.90,
        "Generic WAF/IPS block page",
    ),
    ResponsePattern(
        "RP-005", "Imperva/Incapsula block",
        r"(incapsula|imperva|incident id|_utmz.*incap)",
        [],
        0.95,
        "Imperva/Incapsula WAF block",
    ),

    # ── Framework-level sanitisation ──────────────────────────────────────────
    ResponsePattern(
        "RP-010", "HTML entity encoding in response",
        r"(&lt;script&gt;|&lt;img|&amp;lt;|&#x3C;|&#60;)",
        ["xss_reflected", "xss_stored"],
        0.92,
        "Payload HTML-entity encoded in response — not executable",
    ),
    ResponsePattern(
        "RP-011", "JavaScript string escaping",
        r'(\\u003c|\\u003e|\\u0022|\\u0027|\\x3c|\\x3e)',
        ["xss_reflected", "xss_dom"],
        0.90,
        "Payload Unicode/hex escaped in JavaScript context",
    ),
    ResponsePattern(
        "RP-012", "SQL parameter binding indicator",
        r"(prepared statement|parameterized|bound parameter|"
        r"PDO::.*bindParam|pg_query_params)",
        ["sqli", "sqli_error", "sqli_blind"],
        0.85,
        "Response indicates prepared statement / parameter binding in use",
    ),

    # ── EA-specific false positive patterns ───────────────────────────────────
    ResponsePattern(
        "RP-020", "CodeIgniter default error page",
        r"(A PHP Error Was Encountered|Severity: Notice|"
        r"Message:.*undefined variable|codeigniter.*error)",
        ["sqli_error"],
        0.85,
        "CodeIgniter generic error page — not a real SQL injection",
    ),
    ResponsePattern(
        "RP-021", "Laravel debug page (unrelated exception)",
        r"(Whoops.*Problem|Illuminate\\.*Exception|"
        r"laravel.*exception.*handler)",
        ["sqli_error", "xss_reflected"],
        0.80,
        "Laravel debug page from unrelated exception — not injection-triggered",
    ),
    ResponsePattern(
        "RP-022", "Ugandan ISP error page mirroring",
        r"(ictea|mtnbusiness|airtelug|pearl.*network).*"
        r"(not found|unavailable|error)",
        ["xss_reflected"],
        0.88,
        "ISP error page that mirrors request URL — not reflected XSS",
    ),
    ResponsePattern(
        "RP-023", "Africa's Talking generic error",
        r"(africastalking.*error|AT.*error.*message|"
        r"code.*100[0-9]|SMSMessageData.*error)",
        ["sqli_error"],
        0.82,
        "Africa's Talking API generic error — contains SQL-like text by design",
    ),
    ResponsePattern(
        "RP-024", "MTN MoMo API standard error response",
        r"(\"code\":\"RCS_ERROR\"|\"code\":\"INVALID_CALLBACK\"|"
        r"MoMo.*invalid|momodeveloper.*error)",
        ["sqli_error", "xss_reflected"],
        0.88,
        "MTN MoMo API standard error response — not injection evidence",
    ),

    # ── SSRF false positives ───────────────────────────────────────────────────
    ResponsePattern(
        "RP-030", "SSRF URL blocked by application",
        r"(invalid url|url not allowed|blocked.*url|"
        r"private.*address.*not allowed|url.*whitelist)",
        ["ssrf"],
        0.93,
        "Application explicitly blocked the SSRF probe URL",
    ),
    ResponsePattern(
        "RP-031", "DNS resolution failure (blind SSRF FP)",
        r"(could not resolve|dns.*failed|"
        r"connection refused|network.*unreachable|ECONNREFUSED)",
        ["ssrf"],
        0.75,
        "Network error — blind SSRF may be real but inconclusive",
    ),
]


# ── Layer 3 — Differential analysis ──────────────────────────────────────────

def differential_similarity(body_a: str, body_b: str) -> float:
    """
    Compute structural similarity between two response bodies.
    Returns float 0.0 (completely different) to 1.0 (identical).

    Uses SequenceMatcher on normalised text to avoid false differences
    from dynamic content (timestamps, session IDs, CSRF tokens).
    """
    if not body_a and not body_b:
        return 1.0
    if not body_a or not body_b:
        return 0.0

    # Normalise dynamic content before comparing
    a_norm = _normalise_for_diff(body_a)
    b_norm = _normalise_for_diff(body_b)

    return difflib.SequenceMatcher(None, a_norm, b_norm).ratio()


def _normalise_for_diff(body: str) -> str:
    """
    Remove dynamic values from a response body before structural comparison.
    Replaces: timestamps, UUIDs, session tokens, CSRF tokens, numeric IDs.
    """
    s = body[:8000]   # Only compare first 8KB — cap comparison cost
    # Timestamps
    s = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', 'TIMESTAMP', s)
    s = re.sub(r'\d{10,13}', 'EPOCH', s)
    # UUIDs
    s = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
               'UUID', s, flags=re.IGNORECASE)
    # CSRF / nonce tokens
    s = re.sub(r'(?i)(csrf|nonce|_token|authenticity_token)["\s:=]+[a-zA-Z0-9+/=]{16,}',
               'TOKEN', s)
    # Session IDs in cookies / JSON
    s = re.sub(r'(?i)(session|sess|PHPSESSID|JSESSIONID)["\s:=]+[a-zA-Z0-9%+/=]{16,}',
               'SESSION', s)
    # Generic long hex/base64 strings (likely tokens)
    s = re.sub(r'[a-zA-Z0-9+/]{40,}={0,2}', 'B64TOKEN', s)
    return s


class DifferentialAnalyser:
    """
    Compares injected response to clean baseline.
    If similarity > threshold, the payload had no visible effect.
    """

    # Similarity above this threshold → likely FP
    # Set deliberately high (0.97) to avoid suppressing real findings
    # with slight body differences
    SIMILARITY_THRESHOLD = 0.97

    def check(
        self,
        finding,
        injected_body: str,
        baseline_body: Optional[str],
    ) -> FPResult:
        """
        Returns FPResult.suppressed() if injected response is too similar
        to the baseline (payload had no effect on output).
        """
        if not baseline_body:
            return FPResult.clean()

        vuln_type = getattr(finding, "vuln_type", "")

        # Time-based blind findings don't use response body for evidence
        if vuln_type in ("sqli_blind",):
            return FPResult.clean()

        # IDOR is based on data presence, not text similarity — skip diff
        if vuln_type == "idor":
            return FPResult.clean()

        similarity = differential_similarity(injected_body, baseline_body)

        if similarity >= self.SIMILARITY_THRESHOLD:
            return FPResult.suppressed(
                f"Injected response {similarity:.1%} similar to baseline — "
                "payload likely had no effect (coincidental pattern match)",
                confidence=round(similarity, 3),
                layer="differential",
                pattern=f"similarity={similarity:.3f}",
            )

        return FPResult.clean()


# ── Layer 4 — Known safe values ────────────────────────────────────────────────

# Parameter names that are always safe to ignore for certain vuln types
_SAFE_PARAMETERS: Dict[str, List[str]] = {
    "sqli":       ["page", "sort", "order", "limit", "offset", "format", "lang",
                   "locale", "theme", "color", "size"],
    "xss_reflected": ["page", "sort", "format", "lang", "locale", "callback"],
    "ssrf":       ["page", "sort", "tab", "section", "step", "color"],
}

# URL path segments that should never trigger IDOR findings
_SAFE_PATH_SEGMENTS = frozenset([
    "v1", "v2", "v3", "api", "public", "static", "assets", "images",
    "css", "js", "fonts", "media", "uploads", "download",
])

# Response body fragments that indicate the server sanitised the payload
_SANITISATION_INDICATORS = re.compile(
    r"""(?xi)
    (
        htmlspecialchars|
        htmlentities|
        strip_tags|
        sanitize|
        sanitise|
        clean_input|
        escapeshellarg|
        addslashes|
        mysql_real_escape_string|
        PDO::quote|
        prepared.*statement|
        bind_param
    )
    """,
    re.IGNORECASE,
)


# ── Main FP engine ─────────────────────────────────────────────────────────────

class FalsePositiveEngine:
    """
    Orchestrates all four FP suppression layers.

    Typical usage by validator.py:
        engine = FalsePositiveEngine()
        result = engine.check(finding, injected_body, baseline_body,
                              status_code, elapsed_ms)
        if result.is_fp:
            # suppress or downgrade the finding
    """

    def __init__(self) -> None:
        self._differential = DifferentialAnalyser()
        self._response_patterns = RESPONSE_FP_PATTERNS
        self._structural_rules = STRUCTURAL_RULES

        # Pre-compile response patterns
        for rp in self._response_patterns:
            try:
                rp._compiled = re.compile(rp.regex, re.IGNORECASE | re.DOTALL)
            except re.error:
                logger.warning("FP engine: invalid regex in %s: %s", rp.pattern_id, rp.regex)
                rp._compiled = re.compile(r"(?!)")   # Never matches

    def check(
        self,
        finding,
        injected_body: str,
        baseline_body: Optional[str] = None,
        status_code: int = 200,
        elapsed_ms: float = 0.0,
    ) -> FPResult:
        """
        Run all four FP suppression layers against a finding.
        Returns the first FP result found, or FPResult.clean().
        """
        vuln_type = getattr(finding, "vuln_type", "")

        # ── Layer 1: Structural rules ──────────────────────────────────────────
        for rule in self._structural_rules:
            if rule.applies_to_vuln_types and vuln_type not in rule.applies_to_vuln_types:
                continue
            result = rule.check(finding, injected_body, status_code, elapsed_ms)
            if result and result.is_fp:
                logger.debug(
                    "FP Layer1 [%s] %s → %s",
                    rule.rule_id, vuln_type, result.reason[:60],
                )
                return result

        # ── Layer 2: Response analysis ─────────────────────────────────────────
        for rp in self._response_patterns:
            if rp.applies_to_vuln_types and vuln_type not in rp.applies_to_vuln_types:
                continue
            if rp.matches(injected_body):
                result = FPResult.suppressed(
                    rp.description,
                    confidence=rp.fp_confidence,
                    layer="response_analysis",
                    pattern=rp.pattern_id,
                )
                logger.debug(
                    "FP Layer2 [%s] %s → %s",
                    rp.pattern_id, vuln_type, rp.name,
                )
                return result

        # ── Layer 3: Differential analysis ────────────────────────────────────
        if baseline_body is not None:
            diff_result = self._differential.check(finding, injected_body, baseline_body)
            if diff_result.is_fp:
                logger.debug(
                    "FP Layer3 differential %s → %s",
                    vuln_type, diff_result.reason[:60],
                )
                return diff_result

        # ── Layer 4: Known safe values ─────────────────────────────────────────
        safe_result = self._check_safe_values(finding, injected_body)
        if safe_result.is_fp:
            logger.debug(
                "FP Layer4 safe_values %s → %s",
                vuln_type, safe_result.reason[:60],
            )
            return safe_result

        return FPResult.clean()

    def check_batch(
        self,
        findings: List,
        response_map: Dict[str, Tuple[str, Optional[str], int, float]],
    ) -> Dict[str, FPResult]:
        """
        Check multiple findings at once.

        Args:
            findings: List of Finding objects
            response_map: finding.id → (injected_body, baseline_body, status_code, elapsed_ms)

        Returns:
            Dict mapping finding.id → FPResult
        """
        results: Dict[str, FPResult] = {}
        for finding in findings:
            fid = getattr(finding, "id", "")
            if fid in response_map:
                body, baseline, status, elapsed = response_map[fid]
                results[fid] = self.check(finding, body, baseline, status, elapsed)
            else:
                results[fid] = FPResult.clean()
        return results

    def _check_safe_values(self, finding, body: str) -> FPResult:
        """Layer 4 — parameter name and sanitisation indicator checks."""
        vuln_type = getattr(finding, "vuln_type", "")
        param_name = getattr(finding, "parameter_name", "").lower()

        # Safe parameter name for this vuln type?
        safe_params = _SAFE_PARAMETERS.get(vuln_type, [])
        if param_name in safe_params:
            return FPResult.suppressed(
                f"Parameter '{param_name}' is in safe-list for {vuln_type}",
                confidence=0.80,
                layer="safe_values",
                pattern=f"safe_param:{param_name}",
            )

        # IDOR — path segment is a known safe value?
        if vuln_type == "idor":
            url = getattr(finding, "url", "")
            from urllib.parse import urlparse
            path_parts = urlparse(url).path.split("/")
            for part in path_parts:
                if part.lower() in _SAFE_PATH_SEGMENTS:
                    pass   # Not sufficient alone — don't suppress

        # Sanitisation function names visible in response body (debug mode)?
        if _SANITISATION_INDICATORS.search(body):
            return FPResult.suppressed(
                "Response body contains sanitisation function names — "
                "application likely escaping input correctly",
                confidence=0.78,
                layer="safe_values",
                pattern="sanitisation_indicator",
            )

        return FPResult.clean()

    def adjust_confidence(self, finding_confidence: float, fp_result: FPResult) -> float:
        """
        Instead of hard suppression, reduce confidence proportionally.
        Used for borderline FP cases (fp_confidence < 0.85).
        Returns adjusted finding confidence.
        """
        if not fp_result.is_fp:
            return finding_confidence
        # Reduce confidence proportionally to FP confidence
        reduction = fp_result.confidence * 0.4
        return max(0.0, round(finding_confidence - reduction, 3))

    @staticmethod
    def should_suppress(fp_result: FPResult, threshold: float = 0.85) -> bool:
        """
        Decision: hard suppress (True) or just reduce confidence (False).
        Hard suppress only when FP confidence ≥ threshold.
        """
        return fp_result.is_fp and fp_result.confidence >= threshold


# ── Suppression stats (for scan metrics) ─────────────────────────────────────

@dataclass
class SuppressionStats:
    """Tracks FP suppression counts across a full scan."""
    total_checked: int = 0
    suppressed: int = 0
    confidence_reduced: int = 0
    by_layer: Dict[str, int] = field(default_factory=lambda: {
        "structural": 0,
        "response_analysis": 0,
        "differential": 0,
        "safe_values": 0,
    })
    by_vuln_type: Dict[str, int] = field(default_factory=dict)

    def record(self, vuln_type: str, fp_result: FPResult, hard_suppress: bool) -> None:
        self.total_checked += 1
        if fp_result.is_fp:
            if hard_suppress:
                self.suppressed += 1
            else:
                self.confidence_reduced += 1
            layer = fp_result.layer
            self.by_layer[layer] = self.by_layer.get(layer, 0) + 1
            self.by_vuln_type[vuln_type] = self.by_vuln_type.get(vuln_type, 0) + 1

    @property
    def suppression_rate(self) -> float:
        if self.total_checked == 0:
            return 0.0
        return round(self.suppressed / self.total_checked, 3)

    def to_dict(self) -> Dict:
        return {
            "total_checked": self.total_checked,
            "suppressed": self.suppressed,
            "confidence_reduced": self.confidence_reduced,
            "suppression_rate": self.suppression_rate,
            "by_layer": self.by_layer,
            "by_vuln_type": self.by_vuln_type,
        }