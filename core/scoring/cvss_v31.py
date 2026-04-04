"""
cvss_v31.py — CVSS v3.1 Calculator

Full implementation of the Common Vulnerability Scoring System v3.1
per the FIRST.org specification:
  https://www.first.org/cvss/v3.1/specification-document

Supports:
  - Base Score calculation (all 8 base metrics)
  - Temporal Score (Exploit Code Maturity, Remediation Level, Report Confidence)
  - Environmental Score (Modified Base Metrics + Impact Subscore adjustments)
  - Vector string parsing and generation
  - Severity label mapping (None/Low/Medium/High/Critical)
  - Human-readable metric label lookup

Design:
  - Pure functions — no state, fully testable
  - Raises ValueError on malformed vector strings (never silently returns 0)
  - All intermediate values match FIRST.org reference calculator to 1 decimal
  - EA regulatory multiplier is applied OUTSIDE this module (in risk_prioritizer)
    so CVSS scores remain standard-compliant
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── Metric definitions ─────────────────────────────────────────────────────────

# Base metric values per CVSS v3.1 spec (Table 14-16)
_BASE_METRICS: Dict[str, Dict[str, float]] = {
    # Attack Vector
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    # Attack Complexity
    "AC": {"L": 0.77, "H": 0.44},
    # Privileges Required (values change when Scope=Changed for PR)
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},   # Scope=Changed PR values
    # User Interaction
    "UI": {"N": 0.85, "R": 0.62},
    # Scope
    "S": {"U": 0.0, "C": 0.0},    # Not a numeric metric — affects formula branching
    # Confidentiality Impact
    "C": {"N": 0.00, "L": 0.22, "H": 0.56},
    # Integrity Impact
    "I": {"N": 0.00, "L": 0.22, "H": 0.56},
    # Availability Impact
    "A": {"N": 0.00, "L": 0.22, "H": 0.56},
}

# Temporal metric values
_TEMPORAL_METRICS: Dict[str, Dict[str, float]] = {
    "E":  {"X": 1.00, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.00},
    "RL": {"X": 1.00, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.00},
    "RC": {"X": 1.00, "U": 0.92, "R": 0.96, "C": 1.00},
}

# Environmental — Modified Base Metrics use same values as base
_ENV_METRICS: Dict[str, Dict[str, float]] = {
    "MAV": {"X": -1, "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "MAC": {"X": -1, "L": 0.77, "H": 0.44},
    "MPR": {"X": -1, "N": 0.85, "L": 0.62, "H": 0.27},
    "MPR_C": {"X": -1, "N": 0.85, "L": 0.68, "H": 0.50},
    "MUI": {"X": -1, "N": 0.85, "R": 0.62},
    "MS":  {"X": -1, "U": 0.0,  "C": 0.0},
    "MC":  {"X": -1, "N": 0.00, "L": 0.22, "H": 0.56},
    "MI":  {"X": -1, "N": 0.00, "L": 0.22, "H": 0.56},
    "MA":  {"X": -1, "N": 0.00, "L": 0.22, "H": 0.56},
    # CR/IR/AR — Requirement levels
    "CR":  {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},
    "IR":  {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},
    "AR":  {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50},
}

# Human-readable metric labels
METRIC_LABELS: Dict[str, Dict[str, str]] = {
    "AV": {
        "N": "Network",
        "A": "Adjacent",
        "L": "Local",
        "P": "Physical",
    },
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
    "E":  {"X": "Not Defined", "U": "Unproven", "P": "Proof-of-Concept",
           "F": "Functional", "H": "High"},
    "RL": {"X": "Not Defined", "O": "Official Fix", "T": "Temporary Fix",
           "W": "Workaround", "U": "Unavailable"},
    "RC": {"X": "Not Defined", "U": "Unknown", "R": "Reasonable", "C": "Confirmed"},
}


# ── Parsed CVSS metrics ────────────────────────────────────────────────────────

@dataclass
class CVSSMetrics:
    """Parsed CVSS v3.1 vector broken into individual metric values."""
    # Base (required)
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S:  str = "U"
    C:  str = "N"
    I:  str = "N"
    A:  str = "N"
    # Temporal (optional)
    E:  str = "X"
    RL: str = "X"
    RC: str = "X"
    # Environmental (optional)
    CR: str = "X"
    IR: str = "X"
    AR: str = "X"
    MAV: str = "X"
    MAC: str = "X"
    MPR: str = "X"
    MUI: str = "X"
    MS:  str = "X"
    MC:  str = "X"
    MI:  str = "X"
    MA:  str = "X"


@dataclass
class CVSSScore:
    """Complete CVSS v3.1 score result."""
    base_score: float
    base_severity: str
    temporal_score: Optional[float] = None
    temporal_severity: Optional[str] = None
    environmental_score: Optional[float] = None
    environmental_severity: Optional[str] = None
    vector_string: str = ""
    metrics: Optional[CVSSMetrics] = None

    @property
    def effective_score(self) -> float:
        """Highest applicable score (environmental > temporal > base)."""
        if self.environmental_score is not None:
            return self.environmental_score
        if self.temporal_score is not None:
            return self.temporal_score
        return self.base_score

    @property
    def effective_severity(self) -> str:
        if self.environmental_severity:
            return self.environmental_severity
        if self.temporal_severity:
            return self.temporal_severity
        return self.base_severity

    def to_dict(self) -> Dict:
        return {
            "vector_string": self.vector_string,
            "base_score": self.base_score,
            "base_severity": self.base_severity,
            "temporal_score": self.temporal_score,
            "temporal_severity": self.temporal_severity,
            "environmental_score": self.environmental_score,
            "environmental_severity": self.environmental_severity,
            "effective_score": self.effective_score,
            "effective_severity": self.effective_severity,
        }


# ── Vector parsing ─────────────────────────────────────────────────────────────

_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/"
    r"AV:([NALP])/"
    r"AC:([LH])/"
    r"PR:([NLH])/"
    r"UI:([NR])/"
    r"S:([UC])/"
    r"C:([NLH])/"
    r"I:([NLH])/"
    r"A:([NLH])"
    r"(/E:[XUPFH])?"
    r"(/RL:[XOTWU])?"
    r"(/RC:[XURC])?"
    r"(/CR:[XLMH])?"
    r"(/IR:[XLMH])?"
    r"(/AR:[XLMH])?"
    r"(/MAV:[XNALP])?"
    r"(/MAC:[XLH])?"
    r"(/MPR:[XNLH])?"
    r"(/MUI:[XNR])?"
    r"(/MS:[XUC])?"
    r"(/MC:[XNLH])?"
    r"(/MI:[XNLH])?"
    r"(/MA:[XNLH])?$"
)


def parse_vector(vector: str) -> CVSSMetrics:
    """
    Parse a CVSS v3.1 vector string into a CVSSMetrics object.
    Raises ValueError on invalid format.
    """
    if not vector:
        raise ValueError("Empty CVSS vector string")

    match = _VECTOR_RE.match(vector.strip())
    if not match:
        raise ValueError(f"Invalid CVSS v3.1 vector: {vector!r}")

    def _extract(group: Optional[str], default: str) -> str:
        if not group:
            return default
        return group.split(":")[1]

    groups = match.groups()
    return CVSSMetrics(
        AV=groups[0],
        AC=groups[1],
        PR=groups[2],
        UI=groups[3],
        S=groups[4],
        C=groups[5],
        I=groups[6],
        A=groups[7],
        E=_extract(groups[8],  "X"),
        RL=_extract(groups[9], "X"),
        RC=_extract(groups[10],"X"),
        CR=_extract(groups[11],"X"),
        IR=_extract(groups[12],"X"),
        AR=_extract(groups[13],"X"),
        MAV=_extract(groups[14],"X"),
        MAC=_extract(groups[15],"X"),
        MPR=_extract(groups[16],"X"),
        MUI=_extract(groups[17],"X"),
        MS=_extract(groups[18], "X"),
        MC=_extract(groups[19], "X"),
        MI=_extract(groups[20], "X"),
        MA=_extract(groups[21], "X"),
    )


def build_vector(m: CVSSMetrics) -> str:
    """Reconstruct a CVSS v3.1 vector string from a CVSSMetrics object."""
    base = (
        f"CVSS:3.1/AV:{m.AV}/AC:{m.AC}/PR:{m.PR}/UI:{m.UI}"
        f"/S:{m.S}/C:{m.C}/I:{m.I}/A:{m.A}"
    )
    temporal = ""
    if any(getattr(m, k) != "X" for k in ("E", "RL", "RC")):
        temporal = f"/E:{m.E}/RL:{m.RL}/RC:{m.RC}"

    env = ""
    env_keys = ("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA")
    if any(getattr(m, k) != "X" for k in env_keys):
        env = (
            f"/CR:{m.CR}/IR:{m.IR}/AR:{m.AR}"
            f"/MAV:{m.MAV}/MAC:{m.MAC}/MPR:{m.MPR}"
            f"/MUI:{m.MUI}/MS:{m.MS}/MC:{m.MC}/MI:{m.MI}/MA:{m.MA}"
        )
    return base + temporal + env


# ── Core calculation functions ────────────────────────────────────────────────

def _roundup(value: float) -> float:
    """
    CVSS v3.1 'Roundup' function — rounds up to 1 decimal place.
    Per spec: smallest value >= input with exactly 1 decimal place.
    """
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return math.floor(int_input / 10_000 + 1) / 10


def _iss(m: CVSSMetrics) -> float:
    """Impact Sub-Score."""
    C = _BASE_METRICS["C"][m.C]
    I = _BASE_METRICS["I"][m.I]
    A = _BASE_METRICS["A"][m.A]
    return 1.0 - ((1.0 - C) * (1.0 - I) * (1.0 - A))


def _ess(m: CVSSMetrics) -> float:
    """Exploitability Sub-Score."""
    AV = _BASE_METRICS["AV"][m.AV]
    AC = _BASE_METRICS["AC"][m.AC]
    PR_key = "PR_C" if m.S == "C" else "PR"
    PR = _BASE_METRICS[PR_key][m.PR]
    UI = _BASE_METRICS["UI"][m.UI]
    return 8.22 * AV * AC * PR * UI


def calculate_base_score(m: CVSSMetrics) -> float:
    """
    Calculate CVSS v3.1 Base Score.
    Returns float in [0.0, 10.0].
    """
    iss = _iss(m)

    if m.S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        return 0.0

    exploitability = _ess(m)

    if m.S == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)

    return _roundup(raw)


def calculate_temporal_score(base_score: float, m: CVSSMetrics) -> float:
    """
    Calculate CVSS v3.1 Temporal Score.
    Returns float in [0.0, 10.0].
    """
    E  = _TEMPORAL_METRICS["E"][m.E]
    RL = _TEMPORAL_METRICS["RL"][m.RL]
    RC = _TEMPORAL_METRICS["RC"][m.RC]
    return _roundup(base_score * E * RL * RC)


def calculate_environmental_score(m: CVSSMetrics) -> float:
    """
    Calculate CVSS v3.1 Environmental Score.
    Returns float in [0.0, 10.0].

    Uses Modified Base Metrics where defined, falling back to Base Metrics.
    """
    def _mod(env_key: str, base_key: str, scope_changed: bool = False) -> float:
        val = _ENV_METRICS[env_key][getattr(m, env_key)]
        if val == -1:   # "X" = Not Defined → use base metric
            if scope_changed and base_key == "PR":
                return _BASE_METRICS["PR_C"][getattr(m, base_key)]
            return _BASE_METRICS[base_key][getattr(m, base_key)]
        return val

    # Determine effective scope
    ms = m.MS
    if ms == "X":
        ms = m.S

    scope_changed = (ms == "C")

    CR = _ENV_METRICS["CR"][m.CR]
    IR = _ENV_METRICS["IR"][m.IR]
    AR = _ENV_METRICS["AR"][m.AR]

    mc = _mod("MC", "C")
    mi = _mod("MI", "I")
    ma = _mod("MA", "A")

    miss = 1.0 - ((1.0 - CR * mc) * (1.0 - IR * mi) * (1.0 - AR * ma))
    miss = min(miss, 0.915)

    if scope_changed:
        m_impact = 7.52 * (miss - 0.029) - 3.25 * ((miss * 0.9731 - 0.02) ** 13)
    else:
        m_impact = 6.42 * miss

    if m_impact <= 0:
        return 0.0

    mav = _mod("MAV", "AV")
    mac = _mod("MAC", "AC")
    mpr = _mod("MPR", "PR", scope_changed)
    mui = _mod("MUI", "UI")

    m_exploit = 8.22 * mav * mac * mpr * mui

    if scope_changed:
        raw = min(1.08 * (m_impact + m_exploit), 10.0)
    else:
        raw = min(m_impact + m_exploit, 10.0)

    # Apply temporal modifiers
    E  = _TEMPORAL_METRICS["E"][m.E]
    RL = _TEMPORAL_METRICS["RL"][m.RL]
    RC = _TEMPORAL_METRICS["RC"][m.RC]

    return _roundup(_roundup(raw) * E * RL * RC)


# ── Severity labels ────────────────────────────────────────────────────────────

def severity_label(score: float) -> str:
    """
    Map a CVSS v3.1 score to a severity label.
    Per FIRST.org specification.
    """
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def severity_color(severity: str) -> str:
    """Map severity label to a hex colour for PDF/HTML reports."""
    return {
        "critical":      "#9B1C1C",
        "high":          "#C05621",
        "medium":        "#B7791F",
        "low":           "#276749",
        "informational": "#2B6CB0",
        "none":          "#718096",
    }.get(severity.lower(), "#718096")


# ── Main calculator class ──────────────────────────────────────────────────────

class CVSSv31Calculator:
    """
    Stateless CVSS v3.1 calculator.

    Primary interface for the orchestrator and scoring pipeline.

    Usage:
        calc = CVSSv31Calculator()
        score = calc.calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        label = calc.severity_label(score)  # "critical"
    """

    def calculate(self, vector: str) -> float:
        """
        Calculate the effective CVSS score for a vector string.
        Returns the base score if no temporal/environmental metrics are set.
        Returns 0.0 on invalid/empty vector (logs warning; does not raise).
        """
        if not vector:
            return 0.0
        try:
            m = parse_vector(vector)
            return self.calculate_from_metrics(m).effective_score
        except ValueError:
            import logging
            logging.getLogger(__name__).warning("Invalid CVSS vector: %s", vector)
            return 0.0

    def calculate_full(self, vector: str) -> CVSSScore:
        """
        Full calculation returning base, temporal, and environmental scores.
        Raises ValueError on invalid vector.
        """
        m = parse_vector(vector)
        return self.calculate_from_metrics(m, vector=vector)

    def calculate_from_metrics(
        self,
        m: CVSSMetrics,
        vector: Optional[str] = None,
    ) -> CVSSScore:
        """Calculate all scores from a parsed CVSSMetrics object."""
        base = calculate_base_score(m)
        base_sev = severity_label(base)

        has_temporal = any(getattr(m, k) != "X" for k in ("E", "RL", "RC"))
        has_env = any(
            getattr(m, k) != "X"
            for k in ("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA")
        )

        temporal = None
        temporal_sev = None
        if has_temporal:
            temporal = calculate_temporal_score(base, m)
            temporal_sev = severity_label(temporal)

        env = None
        env_sev = None
        if has_env:
            env = calculate_environmental_score(m)
            env_sev = severity_label(env)

        return CVSSScore(
            base_score=base,
            base_severity=base_sev,
            temporal_score=temporal,
            temporal_severity=temporal_sev,
            environmental_score=env,
            environmental_severity=env_sev,
            vector_string=vector or build_vector(m),
            metrics=m,
        )

    def severity_label(self, score: float) -> str:
        return severity_label(score)

    def severity_color(self, severity: str) -> str:
        return severity_color(severity)

    def explain(self, vector: str) -> Dict:
        """
        Return a human-readable explanation of every metric in a vector.
        Used in technical reports.
        """
        try:
            m = parse_vector(vector)
        except ValueError as e:
            return {"error": str(e)}

        score = self.calculate_full(vector)

        return {
            "vector": vector,
            "scores": score.to_dict(),
            "metrics": {
                "attack_vector":       METRIC_LABELS["AV"].get(m.AV, m.AV),
                "attack_complexity":   METRIC_LABELS["AC"].get(m.AC, m.AC),
                "privileges_required": METRIC_LABELS["PR"].get(m.PR, m.PR),
                "user_interaction":    METRIC_LABELS["UI"].get(m.UI, m.UI),
                "scope":               METRIC_LABELS["S"].get(m.S, m.S),
                "confidentiality":     METRIC_LABELS["C"].get(m.C, m.C),
                "integrity":           METRIC_LABELS["I"].get(m.I, m.I),
                "availability":        METRIC_LABELS["A"].get(m.A, m.A),
            },
            "interpretation": self._interpret(m, score),
        }

    @staticmethod
    def _interpret(m: CVSSMetrics, score: CVSSScore) -> str:
        parts = []
        if m.AV == "N":
            parts.append("exploitable remotely over the network without physical access")
        elif m.AV == "A":
            parts.append("requires adjacent network access")
        if m.AC == "L":
            parts.append("low attack complexity (no special conditions required)")
        else:
            parts.append("requires specific conditions to exploit")
        if m.PR == "N":
            parts.append("no authentication needed")
        elif m.PR == "L":
            parts.append("requires low-privilege authentication")
        if m.UI == "N":
            parts.append("no user interaction required")
        if m.C == "H":
            parts.append("complete confidentiality impact (full data disclosure possible)")
        if m.I == "H":
            parts.append("complete integrity impact (data modification possible)")
        if m.A == "H":
            parts.append("complete availability impact (service disruption possible)")

        base = "; ".join(parts).capitalize() + "."
        return f"Base score {score.base_score} ({score.base_severity.upper()}). {base}"

    # ── Convenience vector builders for common vulnerability types ─────────────

    @staticmethod
    def vector_for_sqli_network() -> str:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    @staticmethod
    def vector_for_xss_reflected() -> str:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    @staticmethod
    def vector_for_idor_auth() -> str:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"

    @staticmethod
    def vector_for_ssrf() -> str:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"

    @staticmethod
    def vector_for_misconfig_info() -> str:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


# ── Quick reference table ──────────────────────────────────────────────────────

COMMON_VECTORS: Dict[str, Tuple[str, str]] = {
    # vuln_type → (vector, description)
    "sqli_network_no_auth":   (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  "9.8 – Critical"
    ),
    "sqli_auth_required":     (
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  "8.8 – High"
    ),
    "xss_reflected":          (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  "6.1 – Medium"
    ),
    "xss_stored":             (
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",  "5.4 – Medium"
    ),
    "xxe_read":               (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",  "8.6 – High"
    ),
    "ssrf":                   (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  "8.2 – High"
    ),
    "idor_low_priv":          (
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",  "7.1 – High"
    ),
    "auth_bypass_network":    (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  "9.8 – Critical"
    ),
    "misconfig_info":         (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  "5.3 – Medium"
    ),
    "sensitive_data_network": (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  "7.5 – High"
    ),
    "ipn_forgery":            (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  "9.8 – Critical"
    ),
    "amount_tampering":       (
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",  "6.5 – Medium"
    ),
}