"""
finding.py — Vulnerability Finding Model

A Finding is the core output unit of VulnScout Pro — one confirmed
vulnerability at one location, with all evidence, scoring, and remediation
context attached.

Design principles:
  - Rich enough to feed directly into a PDF report without post-processing
  - CVSS vector stored as a string (standard notation) alongside calculated score
  - EA context is a first-class field, not an afterthought
  - Proof-of-concept is stored separately from the finding (never auto-shared)
  - All timestamps in UTC ISO 8601
  - Serialises to a flat dict suitable for JSON storage and CSV export

Finding lifecycle:
  detector.detect() → raw Finding (confidence < 1, no score)
  validator.validate() → confirmed Finding (confidence set)
  orchestrator._score_findings() → scored Finding (cvss_score + severity)
  report_builder.build() → Finding with remediation context injected
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Severity levels ────────────────────────────────────────────────────────────

class Severity:
    CRITICAL      = "critical"
    HIGH          = "high"
    MEDIUM        = "medium"
    LOW           = "low"
    INFORMATIONAL = "informational"

    ALL = [CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL]

    @staticmethod
    def from_cvss(score: float) -> str:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW
        return Severity.INFORMATIONAL

    @staticmethod
    def sort_key(severity: str) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }
        return order.get(severity, 5)


# ── Vulnerability type registry ────────────────────────────────────────────────

class VulnType:
    SQLI            = "sqli"
    SQLI_BLIND      = "sqli_blind"
    SQLI_ERROR      = "sqli_error"
    XSS_REFLECTED   = "xss_reflected"
    XSS_STORED      = "xss_stored"
    XSS_DOM         = "xss_dom"
    XXE             = "xxe"
    SSRF            = "ssrf"
    IDOR            = "idor"
    AUTH_BYPASS     = "auth_bypass"
    BROKEN_AUTH     = "broken_auth"
    MISCONFIG       = "misconfig"
    SENSITIVE_DATA  = "sensitive_data"
    OPEN_REDIRECT   = "open_redirect"
    CSRF            = "csrf"

    UNKNOWN             = "unknown"

    # API Security
    API_BOLA            = "api_bola"
    API_MASS_ASSIGNMENT = "api_mass_assignment"
    API_VERB_TAMPERING  = "api_verb_tampering"
    API_INVENTORY       = "api_improper_inventory"

    # Business Logic
    PRICE_MANIPULATION  = "price_manipulation"
    COUPON_ABUSE        = "coupon_abuse"
    PARAM_POLLUTION     = "parameter_pollution"
    WORKFLOW_BYPASS     = "workflow_bypass"

    # Server Side
    SSTI                = "ssti"
    COMMAND_INJECTION   = "command_injection"

    LABELS: Dict[str, str] = {
        "sqli": "SQL Injection",
        "sqli_blind": "Blind SQL Injection",
        "sqli_error": "Error-Based SQL Injection",
        "xss_reflected": "Reflected Cross-Site Scripting",
        "xss_stored": "Stored Cross-Site Scripting",
        "xss_dom": "DOM-Based Cross-Site Scripting",
        "xxe": "XML External Entity (XXE)",
        "ssrf": "Server-Side Request Forgery",
        "idor": "Insecure Direct Object Reference",
        "auth_bypass": "Authentication Bypass",
        "broken_auth": "Broken Authentication",
        "misconfig": "Security Misconfiguration",
        "sensitive_data": "Sensitive Data Exposure",
        "open_redirect": "Open Redirect",
        "csrf": "Cross-Site Request Forgery",
        "unknown": "Unknown Vulnerability",
        "api_bola": "Broken Object Level Authorization (BOLA)",
        "api_mass_assignment": "API Mass Assignment",
        "api_verb_tampering": "API Verb Tampering",
        "api_improper_inventory": "Improper API Inventory Management",
        "price_manipulation": "Business Logic: Price Manipulation",
        "coupon_abuse": "Business Logic: Coupon Abuse",
        "parameter_pollution": "HTTP Parameter Pollution",
        "workflow_bypass": "Business Logic: Workflow Bypass",
        "ssti": "Server-Side Template Injection",
        "command_injection": "OS Command Injection",
    }

    @classmethod
    def label(cls, vuln_type: str) -> str:
        return cls.LABELS.get(vuln_type, vuln_type.replace("_", " ").title())


# ── Evidence ───────────────────────────────────────────────────────────────────

@dataclass
class FindingEvidence:
    """
    Technical evidence that supports a finding.
    Stored separately so it can be redacted from executive reports.
    """
    request_method: str = ""
    request_url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    injected_parameter: str = ""
    injected_payload: str = ""
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body_excerpt: str = ""     # First 2000 chars of relevant portion
    matched_pattern: str = ""           # The regex/string that confirmed the finding
    timing_delta_ms: float = 0.0        # For time-based findings

    def redact_sensitive(self) -> "FindingEvidence":
        """Return a copy with sensitive values masked."""
        import copy
        clone = copy.deepcopy(self)
        # Redact auth headers
        sensitive_headers = {"authorization", "cookie", "x-api-key", "x-auth-token"}
        for h in list(clone.request_headers.keys()):
            if h.lower() in sensitive_headers:
                clone.request_headers[h] = "[REDACTED]"
        for h in list(clone.response_headers.keys()):
            if h.lower() in sensitive_headers:
                clone.response_headers[h] = "[REDACTED]"
        return clone

    def to_dict(self, redact: bool = True) -> Dict:
        src = self.redact_sensitive() if redact else self
        return {
            "request": {
                "method": src.request_method,
                "url": src.request_url,
                "headers": src.request_headers,
                "body": src.request_body[:500] if src.request_body else "",
                "injected_parameter": src.injected_parameter,
                "injected_payload": src.injected_payload,
            },
            "response": {
                "status_code": src.response_status,
                "headers": src.response_headers,
                "body_excerpt": src.response_body_excerpt[:2000],
                "matched_pattern": src.matched_pattern,
            },
            "timing_delta_ms": round(src.timing_delta_ms, 2),
        }


# ── Remediation ────────────────────────────────────────────────────────────────

@dataclass
class RemediationGuide:
    """
    Actionable fix guidance attached to a finding.
    Populated by the report builder using the vuln_type.
    """
    summary: str = ""
    steps: List[str] = field(default_factory=list)
    code_examples: Dict[str, str] = field(default_factory=dict)   # lang → snippet
    references: List[str] = field(default_factory=list)
    effort_estimate: str = ""       # "< 1 hour", "1-2 days", "1 week"
    ea_specific_notes: str = ""     # Uganda/EA-specific remediation context

    def to_dict(self) -> Dict:
        return {
            "summary": self.summary,
            "steps": self.steps,
            "code_examples": self.code_examples,
            "references": self.references,
            "effort_estimate": self.effort_estimate,
            "ea_specific_notes": self.ea_specific_notes,
        }





# ── Finding model ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """
    A single confirmed vulnerability at a specific location.

    Lifecycle notes:
      - id: auto-generated UUID, stable for the life of the finding
      - fingerprint: structural hash for deduplication (same vuln + url + param)
      - confidence: set by validator (0.0–1.0)
      - cvss_score / severity: set by orchestrator after validation
      - remediation / ea_context: injected by report builder
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""

    # Location
    url: str = ""
    parameter_name: str = ""
    parameter_location: str = ""    # query, body, json, header, cookie, path

    # Vulnerability classification
    vuln_type: str = ""
    vuln_label: str = ""            # Human-readable label (auto-set in __post_init__)
    owasp_category: str = ""        # e.g. "A03:2021 – Injection"
    cwe_id: Optional[int] = None    # CWE number

    # Scoring (set by orchestrator)
    cvss_vector: str = ""
    cvss_score: float = 0.0
    severity: str = Severity.INFORMATIONAL
    risk_priority: int = 0          # 1 (highest) to N, relative within scan

    # Validation (set by validator)
    confidence: float = 0.0         # 0.0–1.0
    confirmation_evidence: str = ""
    false_positive_signals: List[str] = field(default_factory=list)

    # Evidence
    evidence: FindingEvidence = field(default_factory=FindingEvidence)
    evidence_pattern: Optional[str] = None   # Regex used for detection
    evidence_status_code: int = 0
    timing_delay_ms: float = 0.0    # For time-based blind findings

    # Injection request reference (for re-probe during validation)
    injection_request: Optional[Any] = None  # InjectionRequest (avoid circular)

    # Context
    technology_context: List[str] = field(default_factory=list)  # Detected tech stack

    # AI Triage & Exploit Chains (set by AITriageEngine)
    ai_triage_score: float = 0.0          # 0.0 to 10.0
    exploit_chain_id: Optional[str] = None
    business_impact: str = ""             # Impact description
    financial_impact_ugx: float = 0.0     # Estimated cost
    predicted_exploitability: float = 0.0 # 0.0 - 1.0
    ai_remediation: List[str] = field(default_factory=list) # Gemini-suggested steps

    # ── Remediation Tracking ──────────────────────────────────────────────────
    remediation_status: str = "open" # open, fixed, verified, ignored, assigned
    remediation_guide:  Dict = field(default_factory=dict)
    assigned_to:        Optional[str] = None
    fixed_at:           Optional[str] = None
    verified_at:        Optional[str] = None

    # Remediation Guidance (injected by report builder)
    remediation: Optional[RemediationGuide] = None

    # Timestamps
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if not self.vuln_label and self.vuln_type:
            self.vuln_label = VulnType.label(self.vuln_type)
        if not self.severity and self.cvss_score:
            self.severity = Severity.from_cvss(self.cvss_score)
        if not self.owasp_category and self.vuln_type:
            self.owasp_category = _OWASP_MAP.get(self.vuln_type, "")

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def fingerprint(self) -> str:
        """
        Structural fingerprint for deduplication.
        Same vuln_type + normalised URL path + parameter = duplicate.
        """
        import re
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        path = re.sub(r"/\d+", "/{id}", parsed.path)
        normalised = f"{parsed.scheme}://{parsed.netloc}{path}"
        raw = f"{self.vuln_type}:{normalised}:{self.parameter_name}"
        return hashlib.md5(raw.encode()).hexdigest()

    @property
    def is_critical_or_high(self) -> bool:
        return self.severity in (Severity.CRITICAL, Severity.HIGH)

    @property
    def severity_sort_key(self) -> int:
        return Severity.sort_key(self.severity)

    @property
    def effective_cvss(self) -> float:
        """Alias for cvss_score (regulatory multiplier removed)."""
        return self.cvss_score

    @property
    def affects_payments(self) -> bool:
        return False

    # ── Serialisation ──────────────────────────────────────────────────────────

    def to_dict(self, include_evidence: bool = True, include_remediation: bool = True) -> Dict:
        result: Dict = {
            "id": self.id,
            "scan_id": self.scan_id,
            "url": self.url,
            "parameter_name": self.parameter_name,
            "parameter_location": self.parameter_location,
            "vuln_type": self.vuln_type,
            "vuln_label": self.vuln_label,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "effective_cvss": self.effective_cvss,
            "severity": self.severity,
            "risk_priority": self.risk_priority,
            "confidence": round(self.confidence, 3),
            "confirmation_evidence": self.confirmation_evidence,
            "technology_context": self.technology_context,
            "ai_triage_score": round(self.ai_triage_score, 2),
            "exploit_chain_id": self.exploit_chain_id,
            "business_impact": self.business_impact,
            "financial_impact_ugx": self.financial_impact_ugx,
            "predicted_exploitability": self.predicted_exploitability,
            "ai_remediation": self.ai_remediation,
            "remediation_status": self.remediation_status,
            "remediation_guide": self.remediation_guide,
            "assigned_to": self.assigned_to,
            "fixed_at": self.fixed_at,
            "verified_at": self.verified_at,
            "affects_payments": self.affects_payments,
            "discovered_at": self.discovered_at,
        }
        if include_evidence:
            result["evidence"] = self.evidence.to_dict(redact=True)
        if include_remediation and self.remediation:
            result["remediation"] = self.remediation.to_dict()
        return result

    def to_csv_row(self) -> Dict[str, str]:
        """Flat dict suitable for CSV export."""
        return {
            "id": self.id,
            "severity": self.severity,
            "cvss_score": str(self.cvss_score),
            "effective_cvss": str(self.effective_cvss),
            "vuln_type": self.vuln_type,
            "vuln_label": self.vuln_label,
            "url": self.url,
            "parameter": self.parameter_name,
            "owasp_category": self.owasp_category,
            "cwe_id": str(self.cwe_id or ""),
            "confidence": str(round(self.confidence, 3)),
            "discovered_at": self.discovered_at,
            "remediation_effort": self.remediation.effort_estimate if self.remediation else "",
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Finding":
        evidence_data = data.pop("evidence", {})
        remediation_data = data.pop("remediation", None)

        finding = cls(
            **{k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        )
        if evidence_data:
            req = evidence_data.get("request", {})
            resp = evidence_data.get("response", {})
            finding.evidence = FindingEvidence(
                request_method=req.get("method", ""),
                request_url=req.get("url", ""),
                request_headers=req.get("headers", {}),
                request_body=req.get("body", ""),
                injected_parameter=req.get("injected_parameter", ""),
                injected_payload=req.get("injected_payload", ""),
                response_status=resp.get("status_code", 0),
                response_headers=resp.get("headers", {}),
                response_body_excerpt=resp.get("body_excerpt", ""),
                matched_pattern=resp.get("matched_pattern", ""),
                timing_delta_ms=evidence_data.get("timing_delta_ms", 0.0),
            )
        if remediation_data:
            finding.remediation = RemediationGuide(**{
                k: v for k, v in remediation_data.items()
                if k in RemediationGuide.__dataclass_fields__
            })
        if "ai_remediation" in data:
            finding.ai_remediation = data["ai_remediation"]
        return finding

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id[:8]} vuln={self.vuln_type!r} "
            f"severity={self.severity} cvss={self.cvss_score} url={self.url!r}>"
        )


# ── OWASP category mapping ─────────────────────────────────────────────────────

_OWASP_MAP: Dict[str, str] = {
    "sqli":                  "A03:2021 – Injection",
    "sqli_blind":            "A03:2021 – Injection",
    "sqli_error":            "A03:2021 – Injection",
    "xss_reflected":         "A03:2021 – Injection",
    "xss_stored":            "A03:2021 – Injection",
    "xss_dom":               "A03:2021 – Injection",
    "xxe":                   "A05:2021 – Security Misconfiguration",
    "ssrf":                  "A10:2021 – Server-Side Request Forgery",
    "idor":                  "A01:2021 – Broken Access Control",
    "auth_bypass":           "A07:2021 – Identification and Authentication Failures",
    "broken_auth":           "A07:2021 – Identification and Authentication Failures",
    "misconfig":             "A05:2021 – Security Misconfiguration",
    "sensitive_data":        "A02:2021 – Cryptographic Failures",
    "open_redirect":         "A01:2021 – Broken Access Control",
    "csrf":                  "A01:2021 – Broken Access Control",
    "csrf":                  "A01:2021 – Broken Access Control",
    "workflow_bypass":       "A04:2021 – Insecure Design",
    "parameter_pollution":   "A03:2021 – Injection",
    "ssti":                  "A03:2021 – Injection",
    "command_injection":     "A03:2021 – Injection",
}


# ── FindingCollection ──────────────────────────────────────────────────────────

class FindingCollection:
    """
    Ordered collection of Findings with filtering and aggregation helpers.
    Used by the report builder and exporters.
    """

    def __init__(self, findings: Optional[List[Finding]] = None) -> None:
        self._findings: List[Finding] = findings or []

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)

    def __len__(self) -> int:
        return len(self._findings)

    def __iter__(self):
        return iter(self._findings)

    # ── Filtering ──────────────────────────────────────────────────────────────

    def by_severity(self, severity: str) -> "FindingCollection":
        return FindingCollection([f for f in self._findings if f.severity == severity])

    def by_severity_gte(self, min_severity: str) -> "FindingCollection":
        threshold = Severity.sort_key(min_severity)
        return FindingCollection(
            [f for f in self._findings if Severity.sort_key(f.severity) <= threshold]
        )

    def by_vuln_type(self, vuln_type: str) -> "FindingCollection":
        return FindingCollection([f for f in self._findings if f.vuln_type == vuln_type])

    def ea_relevant(self) -> "FindingCollection":
        return FindingCollection([f for f in self._findings if f.ea_context.ea_relevant])

    def payment_related(self) -> "FindingCollection":
        return FindingCollection([f for f in self._findings if f.affects_payments])

    def sorted_by_risk(self) -> "FindingCollection":
        return FindingCollection(
            sorted(self._findings, key=lambda f: (f.severity_sort_key, -f.effective_cvss))
        )

    # ── Aggregation ────────────────────────────────────────────────────────────

    @property
    def stats(self) -> Dict:
        total = len(self._findings)
        by_sev: Dict[str, int] = {s: 0 for s in Severity.ALL}
        by_type: Dict[str, int] = {}
        for f in self._findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

        avg_cvss = (
            round(sum(f.cvss_score for f in self._findings) / total, 2)
            if total else 0.0
        )

        return {
            "total": total,
            "by_severity": by_sev,
            "by_vuln_type": by_type,
            "average_cvss": avg_cvss,
            "highest_cvss": max((f.cvss_score for f in self._findings), default=0.0),
        }

    def to_list(self, include_evidence: bool = True) -> List[Dict]:
        return [f.to_dict(include_evidence=include_evidence) for f in self._findings]

    def to_csv_rows(self) -> List[Dict[str, str]]:
        return [f.to_csv_row() for f in self._findings]