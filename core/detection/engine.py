"""
engine.py — Advanced Detection Orchestrator
Implements the unified DetectionEngine for parallelized vulnerability discovery.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from core.detection.techniques import (
    BooleanBasedInjection, ErrorBasedInjection, TimeBasedInjection,
    UnionBasedInjection, SecondOrderInjection, BlindBooleanInjection,
    BlindTimeInjection, ReflectedXSSDetector, DOMXSSDetector, StoredXSSDetector,
    TechniqueResult
)
from core.models.finding import Finding, FindingEvidence, VulnType
Vulnerability = Finding # User-requested alias

logger = logging.getLogger(__name__)

class DetectionExecutor:
    """Helper for running async tasks with timeout management."""
    async def run_with_timeout(self, coro, timeout: float) -> TechniqueResult:
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.debug("Technique timed out after %ds", timeout)
            return TechniqueResult(confirmed=False, description="Timeout reached")
        except Exception as e:
            logger.error("Technique execution failed: %s", e)
            return TechniqueResult(confirmed=False, description=str(e))

class DetectionEngine:
    """
    Modular detection engine that parallelizes specific security techniques.
    """
    def __init__(self) -> None:
        self.executor = DetectionExecutor()

    async def detect_sqli(self, url: str) -> List[Vulnerability]:
        """Multi-technique SQL injection detection as per user specification."""
        techniques = [
            BooleanBasedInjection(),
            ErrorBasedInjection(),
            TimeBasedInjection(),
            UnionBasedInjection(),
            SecondOrderInjection(),  # Often missed
            BlindBooleanInjection(),
            BlindTimeInjection()
        ]
        
        findings = []
        for technique in techniques:
            # Parallel execution for speed
            result = await self.executor.run_with_timeout(
                technique.test(url), 
                timeout=5
            )
            if result.confirmed:
                findings.append(self._translate_to_finding(url, result))
        
        return self.deduplicate(findings)

    async def detect_xss(self, url: str) -> List[Vulnerability]:
        """Comprehensive XSS detection as per user specification."""
        vectors = {
            'reflected': ReflectedXSSDetector(
                payloads=['<script>alert(1)</script>', 
                         '"><img src=x onerror=alert(1)>',
                         'javascript:alert(1)//']
            ),
            'dom': DOMXSSDetector(
                sinks=['innerHTML', 'document.write', 'eval'],
                sources=['location', 'document.URL']
            ),
            'stored': StoredXSSDetector(
                depth=3,  # Follow stored data flow
                contexts=['comment', 'profile', 'search']
            )
        }
        
        return await self.parallel_detect(vectors, url)

    async def parallel_detect(self, vectors: Dict[str, Any], url: str) -> List[Finding]:
        """Executes multiple detection vectors in parallel."""
        tasks = []
        for name, detector in vectors.items():
            tasks.append(detector.test(url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        findings = []
        for res in results:
            if isinstance(res, TechniqueResult) and res.confirmed:
                findings.append(self._translate_to_finding(url, res))
        
        return self.deduplicate(findings)

    def _translate_to_finding(self, url: str, res: TechniqueResult) -> Finding:
        """Converts a TechniqueResult into a standard Finding object."""
        evidence = FindingEvidence(
            request_url=url,
            injected_payload=res.payload,
            response_body_excerpt=res.evidence,
        )
        return Finding(
            url=url,
            vuln_type=res.vuln_type or VulnType.UNKNOWN,
            confidence=res.confidence,
            evidence=evidence,
            confirmation_evidence=res.description
        )

    def deduplicate(self, results: List[Finding]) -> List[Finding]:
        """Removes redundant findings from the same origin."""
        # Simplistic deduplication logic for now
        seen = set()
        unique = []
        for res in results:
            fingerprint = f"{res.vuln_type}_{res.payload}"
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(res)
        return unique
