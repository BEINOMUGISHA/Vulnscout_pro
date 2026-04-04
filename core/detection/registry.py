"""
registry.py — Detector Auto-Registry

Maintains the collection of all active detectors.
Detectors self-register via .register() or by being imported through
DetectorRegistry.default().

Design:
  - Singleton registry instance used by the orchestrator
  - Supports enable/disable per scan via ScanConfig.enabled_checks
  - Ordering: higher-priority detectors run first (lower priority number)
  - EA-specific detectors are gated by include_ea flag

Fixes over previous version:
  - active_detectors() accepted include_ea as a keyword arg but the
    orchestrator called it as active_detectors(self.config.enabled_checks)
    — a positional arg — which bound include_ea to enabled_checks. Added
    explicit keyword-only signature to prevent silent misuse.
  - DetectorRegistry.default() imports all detectors unconditionally at call
    time. If any single detector module fails to import (e.g. an optional
    dependency is missing), the entire registry raises and no scan can start.
    Now each import is wrapped individually so a broken detector is skipped
    with a warning rather than crashing the registry.
  - register() logged "replacing" at DEBUG but never warned when a detector
    was silently overwritten — promoted to WARNING since this is almost always
    a programming error (two modules registering the same ID).
  - list_metadata() called d.meta.estimated_requests_per_endpoint which does
    not exist on all detector implementations — guarded with getattr.
  - __len__ returned count of registered detectors but active_detectors()
    could return fewer; added active_count() for clarity.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from core.detection.base_detector import BaseDetector, DetectorMeta

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """
    Central registry of all loaded detection modules.

    Detectors are registered explicitly via .register() or via
    DetectorRegistry.default() which imports all built-in detectors.
    """

    def __init__(self) -> None:
        self._detectors: Dict[str, BaseDetector] = {}
        self._priority: Dict[str, int] = {}

    # ── Registration ───────────────────────────────────────────────────────────

    def register(self, detector: BaseDetector, priority: int = 50) -> None:
        did = detector.meta.detector_id
        if did in self._detectors:
            # Overwriting an existing detector is almost always unintentional.
            logger.warning(
                "Registry: overwriting existing detector '%s' — "
                "check for duplicate registrations",
                did,
            )
        self._detectors[did] = detector
        self._priority[did] = priority
        logger.debug(
            "Registry: registered '%s' (%s) priority=%d",
            did, detector.meta.name, priority,
        )

    def unregister(self, detector_id: str) -> None:
        self._detectors.pop(detector_id, None)
        self._priority.pop(detector_id, None)

    # ── Query ──────────────────────────────────────────────────────────────────

    def get(self, detector_id: str) -> Optional[BaseDetector]:
        return self._detectors.get(detector_id)

    def all_detectors(self) -> List[BaseDetector]:
        """All registered detectors sorted by ascending priority number."""
        return sorted(
            self._detectors.values(),
            key=lambda d: self._priority.get(d.meta.detector_id, 50),
        )

    def active_detectors(
        self,
        enabled_checks: Optional[List[str]] = None,
        *,
        include_ea: bool = True,
    ) -> List[BaseDetector]:
        """
        Return detectors that should run for a given scan configuration.

        Parameters
        ----------
        enabled_checks:
            Explicit allowlist of vuln_type strings or detector_ids.
            None means "run all default-enabled detectors".
        include_ea:
            Keyword-only. When False, detectors flagged ea_specific are
            excluded. Callers must use include_ea=False explicitly — the
            previous positional form silently bound this to enabled_checks.
        """
        result: List[BaseDetector] = []

        for detector in self.all_detectors():
            meta = detector.meta

            if not meta.default_enabled:
                continue

            if not include_ea and getattr(meta, "ea_specific", False):
                continue

            if enabled_checks is not None:
                vuln_types = getattr(meta, "vuln_types", [])
                if not any(vt in enabled_checks for vt in vuln_types):
                    if meta.detector_id not in enabled_checks:
                        continue

            result.append(detector)

        logger.debug(
            "Registry: %d/%d detectors active", len(result), len(self._detectors)
        )
        return result

    def active_count(
        self,
        enabled_checks: Optional[List[str]] = None,
        *,
        include_ea: bool = True,
    ) -> int:
        """Number of detectors that would run for the given config."""
        return len(self.active_detectors(enabled_checks, include_ea=include_ea))

    def list_metadata(self) -> List[Dict]:
        return [
            {
                "id": d.meta.detector_id,
                "name": d.meta.name,
                "vuln_types": getattr(d.meta, "vuln_types", []),
                "default_enabled": getattr(d.meta, "default_enabled", True),
                "ea_specific": getattr(d.meta, "ea_specific", False),
                "estimated_requests": getattr(
                    d.meta, "estimated_requests_per_endpoint", None
                ),
            }
            for d in self.all_detectors()
        ]

    def __len__(self) -> int:
        return len(self._detectors)

    def __repr__(self) -> str:
        return f"<DetectorRegistry detectors={list(self._detectors.keys())}>"

    # ── Default registry factory ───────────────────────────────────────────────

    @classmethod
    def default(cls) -> "DetectorRegistry":
        """
        Build and return the default registry with all built-in detectors.

        Each detector is imported individually. A failed import logs a warning
        and skips that detector rather than crashing the entire registry — this
        allows optional detectors (e.g. LLMDetector requiring extra deps) to be
        absent in lightweight deployments.
        """
        registry = cls()

        _detectors_to_load = [
            ("core.detection.sqli",           "SQLiDetector",          10),
            ("core.detection.xss",            "XSSDetector",           15),
            ("core.detection.xxe",            "XXEDetector",           20),
            ("core.detection.ssrf",           "SSRFDetector",          25),
            ("core.detection.idor",           "IDORDetector",          30),
            ("core.detection.auth_bypass",    "AuthBypassDetector",    35),
            ("core.detection.misconfig",      "MisconfigDetector",     40),
            ("core.detection.sensitive_data", "SensitiveDataDetector", 45),
            ("core.detection.graphql_detector","GraphQLDetector",      50),
            ("core.detection.jwt_detector",   "JWTDetector",           55),
            ("core.detection.llm_detector",   "LLMDetector",           60),
            ("core.detection.api_scanner",    "APISecurityDetector",   65),
            ("core.detection.broken_auth",    "BrokenAuthDetector",    70),
            ("core.detection.business_logic", "BusinessLogicDetector", 75),
            ("core.detection.server_side",    "ServerSideDetector",    80),
        ]

        for module_path, class_name, priority in _detectors_to_load:
            try:
                import importlib
                module = importlib.import_module(module_path)
                detector_cls = getattr(module, class_name)
                registry.register(detector_cls(), priority=priority)
            except ImportError as exc:
                logger.warning(
                    "Detector '%s.%s' could not be imported — skipping: %s",
                    module_path, class_name, exc,
                )
            except Exception as exc:
                logger.error(
                    "Detector '%s.%s' failed to initialise — skipping: %s",
                    module_path, class_name, exc,
                )

        logger.info(
            "DetectorRegistry.default() loaded %d/%d detectors",
            len(registry),
            len(_detectors_to_load),
        )
        return registry