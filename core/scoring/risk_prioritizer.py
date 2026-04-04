"""
risk_prioritizer.py — EA-Aware Risk Prioritiser

Takes a scored finding (CVSS base score + severity already set) and
produces a final risk_priority integer and enriched context that reflects:

  1. CVSS base score                      (universal baseline)
  2. EA regulatory multiplier             (BOU, UCC, NITA-U, FIA)
  3. Business context factors             (payments, PII, agent network)
  4. Exploitability adjustments           (public exploits, active attacks)
  5. Asset criticality                    (payment gateway vs static page)
  6. Attack chain potential               (finding chains with others)
  7. Confidence weighting                 (unverified findings ranked lower)

Output:
  - finding.risk_priority  — integer 1..N (1 = most urgent, N = least)
  - finding.effective_cvss — CVSS × regulatory multiplier (capped at 10.0)

Scoring formula:
  composite_score = base_cvss
                  × regulatory_multiplier
                  × exploitability_factor
                  × asset_criticality
                  × confidence_weight
                  + chain_bonus
                  + ea_context_bonus

  risk_priority = rank by composite_score descending
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Factor tables ──────────────────────────────────────────────────────────────

# Regulatory multipliers per vuln_type × industry
# Applied on top of base CVSS score to reflect real-world breach cost
_REGULATORY_MULTIPLIERS: Dict[str, Dict[str, float]] = {
    # vuln_type → {industry: multiplier}
    "sqli": {
        "banking": 1.4, "fintech": 1.4, "mobile_money": 1.4,
        "sacco": 1.35, "microfinance": 1.35, "government": 1.3,
        "general": 1.2,
    },
    "sqli_blind": {
        "banking": 1.4, "fintech": 1.4, "mobile_money": 1.4,
        "sacco": 1.35, "general": 1.2,
    },
    "sqli_error": {
        "banking": 1.4, "fintech": 1.4, "mobile_money": 1.4,
        "general": 1.2,
    },
    "idor": {
        "banking": 1.4, "fintech": 1.4, "mobile_money": 1.5,
        "sacco": 1.4, "microfinance": 1.35, "government": 1.4,
        "general": 1.25,
    },
    "auth_bypass": {
        "banking": 1.5, "fintech": 1.5, "mobile_money": 1.5,
        "sacco": 1.4, "telecom": 1.3, "general": 1.2,
    },
    "sensitive_data": {
        "banking": 1.5, "fintech": 1.4, "mobile_money": 1.5,
        "sacco": 1.4, "government": 1.45, "telecom": 1.3,
        "general": 1.3,
    },
    "mm_credential_exposure": {
        "banking": 1.5, "fintech": 1.5, "mobile_money": 1.5,
        "general": 1.4,
    },
    "ipn_forgery": {
        "banking": 1.5, "fintech": 1.5, "mobile_money": 1.5,
        "e-commerce": 1.4, "general": 1.3,
    },
    "amount_tampering": {
        "banking": 1.5, "fintech": 1.5, "mobile_money": 1.5,
        "e-commerce": 1.4, "general": 1.3,
    },
    "xss_reflected": {
        "banking": 1.3, "fintech": 1.3, "mobile_money": 1.3,
        "general": 1.1,
    },
    "xss_stored": {
        "banking": 1.35, "fintech": 1.35, "mobile_money": 1.35,
        "general": 1.2,
    },
    "xxe": {
        "banking": 1.4, "fintech": 1.4, "mobile_money": 1.4,
        "general": 1.2,
    },
    "ssrf": {
        "banking": 1.35, "fintech": 1.35, "mobile_money": 1.35,
        "general": 1.15,
    },
    "misconfig": {
        "banking": 1.2, "fintech": 1.2, "mobile_money": 1.3,
        "government": 1.25, "general": 1.1,
    },
}

# Exploitability factors — does active exploit tooling exist?
_EXPLOITABILITY_FACTORS: Dict[str, float] = {
    "sqli":                1.15,   # SQLMap widely available
    "sqli_blind":          1.10,
    "sqli_error":          1.20,
    "xss_reflected":       1.10,
    "xss_stored":          1.15,
    "xss_dom":             1.05,
    "xxe":                 1.10,
    "ssrf":                1.10,
    "idor":                1.20,   # No tooling needed — manual or simple script
    "auth_bypass":         1.20,
    "broken_auth":         1.15,
    "misconfig":           1.10,
    "sensitive_data":      1.25,   # Passive read — trivial to exploit
    "mm_credential_exposure": 1.30,
    "ipn_forgery":         1.25,
    "amount_tampering":    1.20,
    "msisdn_spoofing":     1.20,
    "ussd_injection":      1.10,
    "open_redirect":       1.05,
}

# Asset criticality multipliers by endpoint pattern
_ASSET_PATTERNS: List[Tuple[str, float]] = [
    # (url_fragment, criticality_multiplier)
    ("payment",        1.30),
    ("checkout",       1.30),
    ("momo",           1.35),
    ("airtel",         1.35),
    ("mobile-money",   1.30),
    ("transfer",       1.25),
    ("transaction",    1.20),
    ("admin",          1.25),
    ("dashboard",      1.15),
    ("api/users",      1.15),
    ("api/accounts",   1.20),
    ("ipn",            1.30),
    ("callback",       1.25),
    ("webhook",        1.20),
    ("agent",          1.20),
    ("merchant",       1.20),
    ("login",          1.15),
    ("auth",           1.10),
    ("kyc",            1.20),
    ("document",       1.10),
]

# Confidence weighting — low confidence findings rank lower
_CONFIDENCE_WEIGHTS: List[Tuple[float, float]] = [
    (0.90, 1.00),   # ≥90% confidence → full weight
    (0.75, 0.90),   # 75–90% → 90% weight
    (0.60, 0.80),   # 60–75% → 80% weight
    (0.45, 0.65),   # 45–60% → 65% weight
    (0.00, 0.50),   # <45%   → 50% weight
]

# Chain bonus — findings that commonly appear together amplify each other
_CHAIN_GROUPS: Dict[str, List[str]] = {
    "sqli_to_rce":          ["sqli", "sqli_error", "sqli_blind"],
    "auth_to_idor":         ["auth_bypass", "idor"],
    "xss_to_account_takeover": ["xss_reflected", "xss_stored", "broken_auth"],
    "mm_full_compromise":   ["mm_credential_exposure", "ipn_forgery", "amount_tampering"],
    "misconfig_to_exploit": ["misconfig", "sensitive_data"],
}

_CHAIN_BONUS = 0.5   # Added to composite score per chain matched


# ── Composite score calculation ────────────────────────────────────────────────

@dataclass
class PriorityResult:
    """Output of a single finding prioritisation."""
    finding_id: str
    composite_score: float
    regulatory_multiplier: float
    exploitability_factor: float
    asset_criticality: float
    confidence_weight: float
    chain_bonus: float
    effective_cvss: float
    factors_applied: List[str] = field(default_factory=list)


def _get_regulatory_multiplier(vuln_type: str, industry: str) -> Tuple[float, str]:
    """Return (multiplier, description) for a vuln_type × industry combination."""
    table = _REGULATORY_MULTIPLIERS.get(vuln_type, {})
    mult = table.get(industry, table.get("general", 1.0))
    if mult > 1.0:
        desc = f"EA regulatory context ({industry}): ×{mult:.2f}"
    else:
        desc = "No regulatory multiplier"
    return mult, desc


def _get_exploitability_factor(vuln_type: str) -> Tuple[float, str]:
    factor = _EXPLOITABILITY_FACTORS.get(vuln_type, 1.0)
    desc = f"Exploitability factor ({vuln_type}): ×{factor:.2f}" if factor > 1.0 else ""
    return factor, desc


def _get_asset_criticality(url: str) -> Tuple[float, str]:
    url_lower = url.lower()
    best = 1.0
    matched = ""
    for fragment, multiplier in _ASSET_PATTERNS:
        if fragment in url_lower and multiplier > best:
            best = multiplier
            matched = fragment
    desc = f"Asset criticality ({matched}): ×{best:.2f}" if matched else ""
    return best, desc


def _get_confidence_weight(confidence: float) -> Tuple[float, str]:
    for threshold, weight in _CONFIDENCE_WEIGHTS:
        if confidence >= threshold:
            return weight, f"Confidence {confidence:.0%} → weight {weight:.2f}"
    return 0.50, f"Low confidence {confidence:.0%}"


def _get_chain_bonus(vuln_type: str, sibling_types: List[str]) -> Tuple[float, str]:
    bonus = 0.0
    chains = []
    for chain_name, chain_types in _CHAIN_GROUPS.items():
        if vuln_type in chain_types:
            if any(s in chain_types for s in sibling_types if s != vuln_type):
                bonus += _CHAIN_BONUS
                chains.append(chain_name)
    desc = f"Attack chain bonus ({', '.join(chains)}): +{bonus:.1f}" if chains else ""
    return bonus, desc



def _get_ai_triage_bonus(vuln_type: str, confidence: float):
    """
    AI-Assisted Triage Bonus.
    Applies an additional urgency score for vulnerability types that are
    highly exploitable in the wild and have been confirmed at high confidence.
    """
    if confidence < 0.8:
        return 0.0, ""

    HIGH_URGENCY = {
        "sqli":              0.8,
        "sqli_blind":        0.7,
        "rce":               1.5,
        "auth_bypass":       0.9,
        "idor":              0.6,
        "ssrf":              0.5,
        "jwt_alg_none":      0.9,
        "llm_prompt_injection": 0.7,
        "graphql_introspection": 0.4,
    }
    bonus = HIGH_URGENCY.get(vuln_type, 0.0)
    if bonus > 0:
        return bonus, f"AI Triage: +{bonus:.1f} urgency for {vuln_type} (confidence={confidence:.2f})"
    return 0.0, ""

def calculate_composite_score(
    base_cvss: float,
    vuln_type: str,
    industry: str,
    url: str,
    confidence: float,
    sibling_vuln_types: Optional[List[str]] = None,
    ai_triage: Optional[any] = None, # Optional AITriageResult
) -> PriorityResult:
    """
    Calculate a composite risk score for a finding.

    Args:
        base_cvss:           Raw CVSS base score (0–10)
        vuln_type:           VulnType identifier
        industry:            Target industry (banking, fintech, general, etc.)
        url:                 Affected URL (for asset criticality)
        confidence:          Validator confidence (0.0–1.0)
        sibling_vuln_types:  Other vuln_types found in the same scan

    Returns:
        PriorityResult with composite_score and all contributing factors
    """
    factors = []

    reg_mult, reg_desc = _get_regulatory_multiplier(vuln_type, industry)
    if reg_desc:
        factors.append(reg_desc)

    exp_factor, exp_desc = _get_exploitability_factor(vuln_type)
    if exp_desc:
        factors.append(exp_desc)

    asset_crit, asset_desc = _get_asset_criticality(url)
    if asset_desc:
        factors.append(asset_desc)

    conf_weight, conf_desc = _get_confidence_weight(confidence)
    factors.append(conf_desc)

    chain_bonus, chain_desc = _get_chain_bonus(vuln_type, sibling_vuln_types or [])
    if chain_desc:
        factors.append(chain_desc)

    ai_bonus, ai_desc = _get_ai_triage_bonus(vuln_type, confidence)
    if ai_desc:
        factors.append(ai_desc)

    # Effective CVSS (regulatory adjusted, capped at 10)
    effective_cvss = min(10.0, round(base_cvss * reg_mult, 1))

    # Full composite score (can exceed 10 due to bonuses; used for ranking only)
    composite = (
        base_cvss
        * reg_mult
        * exp_factor
        * asset_crit
        * conf_weight
        + chain_bonus
        + ai_bonus
    )
    
    # If AI impact score is available, it heavily influences the composite
    if ai_triage:
        # Support both AITriageResult object and Finding object with ai_triage traits
        impact_score = getattr(ai_triage, "business_impact_score", getattr(ai_triage, "ai_triage_score", 0.0))
        chain_potential = getattr(ai_triage, "exploit_chain_potential", False)
        
        composite += (impact_score * 0.5)
        if chain_potential:
            composite += 1.0

    composite = round(composite, 4)

    return PriorityResult(
        finding_id="",
        composite_score=composite,
        regulatory_multiplier=reg_mult,
        exploitability_factor=exp_factor,
        asset_criticality=asset_crit,
        confidence_weight=conf_weight,
        chain_bonus=chain_bonus,
        effective_cvss=effective_cvss,
        factors_applied=factors,
    )


# ── Prioritiser class ──────────────────────────────────────────────────────────

class RiskPrioritizer:
    """
    Assigns risk_priority (integer rank) and effective_cvss to all findings
    in a scan.

    Typical usage by orchestrator:
        prioritizer = RiskPrioritizer()
        for finding in findings:
            finding.risk_priority = prioritizer.prioritize(finding, industry="fintech")

    Or batch mode (preferred — enables chain detection):
        ranked = prioritizer.prioritize_all(findings, industry="fintech")
    """

    def prioritize(
        self,
        finding,
        industry: str = "general",
        sibling_vuln_types: Optional[List[str]] = None,
    ) -> int:
        """
        Compute a composite score for a single finding and return a priority integer.
        Without sibling context, chain bonuses cannot be applied.
        Returns 1 always (use prioritize_all for ranked output).
        """
        result = calculate_composite_score(
            base_cvss=getattr(finding, "cvss_score", 0.0),
            vuln_type=getattr(finding, "vuln_type", ""),
            industry=industry,
            url=getattr(finding, "url", ""),
            confidence=getattr(finding, "confidence", 0.5),
            sibling_vuln_types=sibling_vuln_types or [],
            ai_triage=finding if hasattr(finding, "ai_triage_score") else None
        )

        # Write effective_cvss back to finding
        if hasattr(finding, "ea_context") and finding.ea_context:
            finding.ea_context.max_regulatory_multiplier = result.regulatory_multiplier
        # effective_cvss is a property on Finding that computes on demand
        # but we store the multiplier so it's available

        result.finding_id = getattr(finding, "id", "")
        return 1   # Rank is set by prioritize_all

    def prioritize_all(
        self,
        findings: List,
        industry: str = "general",
    ) -> List:
        """
        Score and rank all findings in a scan.
        Returns findings sorted by priority (highest risk first).
        Mutates finding.risk_priority and ea_context.max_regulatory_multiplier.
        """
        if not findings:
            return []

        # Collect all vuln types for chain detection
        all_types = [getattr(f, "vuln_type", "") for f in findings]

        scored: List[Tuple[float, object]] = []

        for finding in findings:
            vuln_type  = getattr(finding, "vuln_type", "")
            base_cvss  = getattr(finding, "cvss_score", 0.0)
            url        = getattr(finding, "url", "")
            confidence = getattr(finding, "confidence", 0.5)
            sibling_types = [t for t in all_types if t != vuln_type]

            result = calculate_composite_score(
                base_cvss=base_cvss,
                vuln_type=vuln_type,
                industry=industry,
                url=url,
                confidence=confidence,
                sibling_vuln_types=sibling_types,
                ai_triage=finding if hasattr(finding, "ai_triage_score") else None
            )
            result.finding_id = getattr(finding, "id", "")

            # Update ea_context with regulatory multiplier
            if hasattr(finding, "ea_context") and finding.ea_context:
                finding.ea_context.max_regulatory_multiplier = result.regulatory_multiplier
                if not finding.ea_context.regulatory_requirements:
                    finding.ea_context.regulatory_requirements = (
                        self._regulatory_requirements_for(vuln_type, industry)
                    )

            scored.append((result.composite_score, finding))
            
            # Write back AI metadata to finding if provided via finding attributes 
            # (assuming orchestrator set them before calling this)
            if hasattr(finding, "ai_triage_score"):
                # Use composite as a proxy for triage score if not already set
                if finding.ai_triage_score == 0:
                    finding.ai_triage_score = min(10.0, result.composite_score)

            logger.debug(
                "Priority score [%s] %s @ %s → composite=%.3f reg×%.2f exp×%.2f",
                vuln_type,
                getattr(finding, "id", "")[:8],
                url[:60],
                result.composite_score,
                result.regulatory_multiplier,
                result.exploitability_factor,
            )

        # Sort descending by composite score
        scored.sort(key=lambda x: x[0], reverse=True)

        # Assign integer priorities (1 = most critical)
        ranked = []
        for rank, (score, finding) in enumerate(scored, start=1):
            if hasattr(finding, "risk_priority"):
                finding.risk_priority = rank
            ranked.append(finding)

        logger.info(
            "Prioritised %d findings — top vuln: %s (score %.2f)",
            len(ranked),
            getattr(ranked[0], "vuln_type", "?") if ranked else "none",
            scored[0][0] if scored else 0.0,
        )
        return ranked

    def generate_priority_report(self, findings: List) -> Dict:
        """
        Produce a priority summary for inclusion in reports.
        Shows top findings and the factors driving their rank.
        """
        if not findings:
            return {"findings": [], "summary": "No findings to prioritise."}

        all_types = [getattr(f, "vuln_type", "") for f in findings]
        rows = []

        for finding in findings[:20]:   # Top 20 for the report
            vuln_type  = getattr(finding, "vuln_type", "")
            base_cvss  = getattr(finding, "cvss_score", 0.0)
            url        = getattr(finding, "url", "")
            confidence = getattr(finding, "confidence", 0.5)
            industry   = "general"

            result = calculate_composite_score(
                base_cvss=base_cvss,
                vuln_type=vuln_type,
                industry=industry,
                url=url,
                confidence=confidence,
                sibling_vuln_types=all_types,
            )

            rows.append({
                "rank": getattr(finding, "risk_priority", 0),
                "id": getattr(finding, "id", "")[:8],
                "vuln_type": vuln_type,
                "vuln_label": getattr(finding, "vuln_label", vuln_type),
                "url": url,
                "base_cvss": base_cvss,
                "effective_cvss": result.effective_cvss,
                "composite_score": round(result.composite_score, 3),
                "regulatory_multiplier": result.regulatory_multiplier,
                "factors": result.factors_applied,
            })

        return {
            "total_findings": len(findings),
            "top_findings": rows,
            "summary": self._generate_summary(findings),
        }

    @staticmethod
    def _generate_summary(findings: List) -> str:
        from core.models.finding import Severity
        critical = sum(1 for f in findings if getattr(f, "severity", "") == Severity.CRITICAL)
        high = sum(1 for f in findings if getattr(f, "severity", "") == Severity.HIGH)
        payment = sum(1 for f in findings if getattr(f, "affects_payments", False))
        ea = sum(1 for f in findings
                 if getattr(getattr(f, "ea_context", None), "ea_relevant", False))

        parts = []
        if critical:
            parts.append(f"{critical} critical finding(s) requiring immediate remediation")
        if high:
            parts.append(f"{high} high-severity finding(s)")
        if payment:
            parts.append(f"{payment} finding(s) affect payment systems")
        if ea:
            parts.append(f"{ea} finding(s) have EA regulatory exposure")
        return "; ".join(parts) + "." if parts else "All findings are low severity."

    @staticmethod
    def _regulatory_requirements_for(vuln_type: str, industry: str) -> List[Dict]:
        """Generate minimal regulatory requirement context for a finding."""
        reqs = []
        if industry in ("banking", "fintech", "mobile_money", "sacco"):
            if vuln_type in ("sqli", "sqli_blind", "sqli_error", "idor", "sensitive_data"):
                reqs.append({
                    "body": "Bank of Uganda",
                    "requirement_id": "BOU-CYBER-2022-01",
                    "description": "BOU Cybersecurity Framework — Data Protection",
                    "risk_multiplier": 1.4,
                    "penalty": "BOU can revoke operating license",
                })
        if vuln_type in ("sensitive_data", "idor", "sqli", "xxe"):
            reqs.append({
                "body": "NITA-U",
                "requirement_id": "NITA-U-PDPA-2019",
                "description": "Uganda Data Protection and Privacy Act 2019",
                "risk_multiplier": 1.35,
                "penalty": "Criminal liability + UGX 500M fine",
            })
        if industry in ("mobile_money", "telecom") and vuln_type in ("auth_bypass", "ipn_forgery", "amount_tampering"):
            reqs.append({
                "body": "Bank of Uganda",
                "requirement_id": "BOU-MM-2017",
                "description": "Mobile Money Guidelines — Transaction Security",
                "risk_multiplier": 1.5,
                "penalty": "Suspension of mobile money license",
            })
        return reqs