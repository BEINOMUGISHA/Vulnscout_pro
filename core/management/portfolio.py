"""
portfolio.py — Enterprise Portfolio and Policy Management

Responsibilities:
  - Group multiple scan targets into logical 'Portfolios' (e.g., By department, business unit)
  - Calculate aggregate risk scores for an entire portfolio
  - Enforce global scan policies (e.g., "All targets in this portfolio must be scanned weekly")
  - Provide cross-target reporting and trend analysis
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Portfolio:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    target_ids: List[str] = field(default_factory=list)
    owner_id: str = ""
    team_id: Optional[str] = None
    default_scan_config: Optional[Dict] = None


class PortfolioManager:
    """
    Manages enterprise portfolios of scan targets.
    """

    def __init__(self, scan_store=None) -> None:
        self.scan_store = scan_store
        self._portfolios: Dict[str, Portfolio] = {}

    async def create_portfolio(self, name: str, owner_id: str, team_id: Optional[str] = None) -> Portfolio:
        p = Portfolio(name=name, owner_id=owner_id, team_id=team_id)
        self._portfolios[p.id] = p
        await self._save_portfolios()
        return p

    async def add_target_to_portfolio(self, portfolio_id: str, target_id: str):
        if portfolio_id in self._portfolios:
            if target_id not in self._portfolios[portfolio_id].target_ids:
                self._portfolios[portfolio_id].target_ids.append(target_id)
                await self._save_portfolios()

    async def get_aggregate_metrics(self, portfolio_id: str) -> Dict:
        """
        Calculate sum and average of risk scores across all targets in portfolio.
        """
        if portfolio_id not in self._portfolios:
            return {}
            
        p = self._portfolios[portfolio_id]
        total_risk = 0.0
        findings_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for tid in p.target_ids:
            target = await self.scan_store.get_target(tid)
            if target:
                # Get most recent scan for this target
                scans, _ = await self.scan_store.list_scans(target_url=target.get("base_url"), limit=1)
                if scans:
                    summary = await self.scan_store.get_summary(scans[0]["scan_id"])
                    if summary:
                        total_risk += summary.get("ea_risk_score", 0.0)
                        stats = summary.get("stats", {})
                        for k in findings_summary:
                            findings_summary[k] += stats.get(k, 0)
                            
        target_count = len(p.target_ids)
        return {
            "portfolio_id": portfolio_id,
            "target_count": target_count,
            "average_risk_score": total_risk / target_count if target_count > 0 else 0.0,
            "aggregate_findings": findings_summary
        }

    async def _save_portfolios(self):
        if self.scan_store:
            data = [vars(p) for p in self._portfolios.values()]
            await asyncio.to_thread(self.scan_store._atomic_write, 
                                   self.scan_store._root / "portfolios.json", data)

    async def _load_portfolios(self):
        if self.scan_store:
            raw = await self.scan_store._load_json(self.scan_store._root / "portfolios.json")
            if isinstance(raw, list):
                for item in raw:
                    p = Portfolio(**item)
                    self._portfolios[p.id] = p
