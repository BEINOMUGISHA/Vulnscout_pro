"""
techniques.py — Modular Vulnerability Detection Techniques
Defines granular detector classes for parallel execution within the DetectionEngine.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from core.models.finding import VulnType

logger = logging.getLogger(__name__)

@dataclass
class TechniqueResult:
    confirmed: bool = False
    vuln_type: Optional[str] = None
    description: str = ""
    evidence: str = ""
    payload: str = ""
    confidence: float = 0.0

class BaseTechnique:
    """Abstract base for all granular detection techniques."""
    def __init__(self, name: str):
        self.name = name

    async def test(self, url: str) -> TechniqueResult:
        raise NotImplementedError("Techniques must implement test()")

# ── SQL Injection Techniques ──────────────────────────────────────────────────

class BooleanBasedInjection(BaseTechnique):
    def __init__(self):
        super().__init__("Boolean-Based SQLi")
        
    async def test(self, url: str) -> TechniqueResult:
        # Implementation would use injecting logic similar to SQLiDetector._test_boolean_differential
        # Placeholder for now to demonstrate structure
        return TechniqueResult(description="Testing boolean differential logic")

class ErrorBasedInjection(BaseTechnique):
    def __init__(self):
        super().__init__("Error-Based SQLi")
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description="Testing for DB error leakage")

class TimeBasedInjection(BaseTechnique):
    def __init__(self):
        super().__init__("Time-Based SQLi")
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description="Measuring response latency shifts")

class UnionBasedInjection(BaseTechnique):
    def __init__(self):
        super().__init__("Union-Based SQLi")
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description="Probing for row concatenation")

class SecondOrderInjection(BaseTechnique):
    def __init__(self):
        super().__init__("Second-Order SQLi")
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description="Tracking deferred execution in storage sinks")

class BlindBooleanInjection(BaseTechnique):
    def __init__(self):
        super().__init__("Blind Boolean SQLi")
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description="Iterative truth-table inference")

class BlindTimeInjection(BaseTechnique):
    def __init__(self):
        super().__init__("Blind Time SQLi")
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description="Heavy-load delay verification")

# ── XSS Techniques ────────────────────────────────────────────────────────────

class ReflectedXSSDetector(BaseTechnique):
    def __init__(self, payloads: List[str] = None):
        super().__init__("Reflected XSS")
        self.payloads = payloads or []
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description=f"Scanning for reflection of {len(self.payloads)} vectors")

class DOMXSSDetector(BaseTechnique):
    def __init__(self, sinks: List[str] = None, sources: List[str] = None):
        super().__init__("DOM XSS")
        self.sinks = sinks or []
        self.sources = sources or []
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description="Analyzing JS source for dangerous sinks")

class StoredXSSDetector(BaseTechnique):
    def __init__(self, depth: int = 1, contexts: List[str] = None):
        super().__init__("Stored XSS")
        self.depth = depth
        self.contexts = contexts or []
        
    async def test(self, url: str) -> TechniqueResult:
        return TechniqueResult(description=f"Crawling deep state (depth={self.depth}) for persistence")
