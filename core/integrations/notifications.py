"""
notifications.py — Outbound Notification Dispatcher

Responsibilities:
  - Dispatch scan events to external platforms (Slack, Teams, Jira, Webhooks)
  - Format findings for different platform requirements (Markdown, JSON, Jira Wiki)
  - Handle rate limiting and retry logic for third-party APIs
  - Authenticate with integration secrets stored in config
"""

from __future__ import annotations

import aiohttp
import json
import logging
import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

logger = logging.getLogger(__name__)


class NotificationDispatcher:
    """
    Central dispatcher for all outbound security notifications.
    """

    def __init__(self, config: Optional[Dict] = None) -> None:
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))

    async def close(self):
        if self.session:
            await self.session.close()

    async def dispatch_scan_complete(self, scan_result: Dict):
        """Notify on scan completion with professional summary."""
        stats = scan_result.get("stats", {})
        target = scan_result.get('target')
        
        # Professional Slack Blocks
        slack_blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🏁 VulnScout Scan Complete"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{target}"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{scan_result.get('duration_seconds')}s"}
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Findings:*\n{stats.get('total')}"},
                    {"type": "mrkdwn", "text": f"*Critical/High:*\n{stats.get('critical')} / {stats.get('high')}"}
                ]
            }
        ]
        
        # Simple text fallback
        text = f"✅ VulnScout Scan Complete: {target} ({stats.get('total')} findings)"
        
        await self._send_to_all(text, scan_result, slack_blocks=slack_blocks)

    async def dispatch_critical_finding(self, finding: Dict):
        """Immediate alert for critical vulnerabilities with detailed impact."""
        label = finding.get('vuln_label')
        url = finding.get('url')
        
        slack_blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 CRITICAL VULNERABILITY"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Type:* {label}\n*URL:* {url}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Business Impact:*\n{finding.get('business_impact')}"},
                    {"type": "mrkdwn", "text": f"*AI Triage Score:*\n{finding.get('ai_triage_score')}/10"}
                ]
            }
        ]
        
        text = f"🚨 CRITICAL: {label} on {url}"
        await self._send_to_all(text, finding, slack_blocks=slack_blocks)
        
        # Also create Jira issue for criticals if configured
        if self.config.get("jira_enabled"):
            await self.create_jira_issue(finding)

    async def _send_to_all(self, text_message: str, data: Dict, slack_blocks: Optional[List] = None):
        await self._ensure_session()
        
        tasks = []
        
        # Slack
        if self.config.get("slack_enabled") and "slack_webhook_url" in self.config:
            tasks.append(self._send_slack(self.config["slack_webhook_url"], text_message, slack_blocks))
            
        # Teams
        if self.config.get("teams_enabled") and "teams_webhook_url" in self.config:
            tasks.append(self._send_teams(self.config["teams_webhook_url"], text_message))
            
        # Generic Webhooks
        if "webhooks" in self.config:
            for wh in self.config["webhooks"]:
                tasks.append(self._send_webhook(wh, data))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def _send_slack(self, url: str, text: str, blocks: Optional[List] = None):
        payload = {"text": text}
        if blocks:
            payload["blocks"] = blocks
            
        async with self.session.post(url, json=payload) as resp:
            if resp.status >= 400:
                logger.error("Slack notification failed: %d", resp.status)
                resp.raise_for_status()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def _send_teams(self, url: str, text: str):
        # Adaptive Card format (legacy MessageCard for stability)
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "E81123",
            "summary": "VulnScout Pro Alert",
            "sections": [{
                "activityTitle": "VulnScout Pro Security Event",
                "activitySubtitle": "Enterprise Integration Relay",
                "text": text,
                "markdown": True
            }]
        }
        async with self.session.post(url, json=payload) as resp:
            if resp.status >= 400:
                logger.error("Teams notification failed: %d", resp.status)
                resp.raise_for_status()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def _send_webhook(self, config: Dict, data: Dict):
        url = config.get("url")
        secret = config.get("secret")
        headers = {"Content-Type": "application/json"}
        if secret:
            headers["X-VulnScout-Signature"] = secret
            
        async with self.session.post(url, json=data, headers=headers) as resp:
            if resp.status >= 400:
                logger.error("Webhook dispatch failed to %s: %d", url, resp.status)
                resp.raise_for_status()

    async def create_jira_issue(self, finding: Dict):
        """Create a detailed Jira ticket for a finding."""
        if not all(k in self.config for k in ["jira_url", "jira_user", "jira_token", "jira_project"]):
            return
            
        url = f"{self.config['jira_url'].rstrip('/')}/rest/api/2/issue"
        auth = aiohttp.BasicAuth(self.config["jira_user"], self.config["jira_token"])
        
        description = (
            f"h2. Vulnerability Details\n"
            f"*Type:* {finding.get('vuln_label')}\n"
            f"*Severity:* {finding.get('severity')}\n"
            f"*CVSS:* {finding.get('cvss_score')}\n"
            f"*URL:* {finding.get('url')}\n"
            f"*Parameter:* {finding.get('parameter_name')}\n\n"
            f"h2. Business Impact\n"
            f"{finding.get('business_impact')}\n\n"
            f"h2. AI Triage Analysis\n"
            f"*Predicted Exploitability:* {finding.get('predicted_exploitability')}\n"
            f"*UGX Impact Estimate:* UGX {finding.get('financial_impact_ugx'):,.0f}\n\n"
            f"h2. Smart Remediation Steps\n"
            + "\n".join([f"* {step}" for step in finding.get('ai_remediation', [])])
        )
        
        payload = {
            "fields": {
                "project": {"key": self.config["jira_project"]},
                "summary": f"[VulnScout] {finding.get('vuln_label')} on {finding.get('url')}",
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": self._map_to_jira_priority(finding.get("severity"))}
            }
        }
        
        try:
            async with self.session.post(url, json=payload, auth=auth) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    logger.error("Jira ticket creation failed: %d - %s", resp.status, body)
                else:
                    res_json = await resp.json()
                    logger.info("Jira issue created: %s", res_json.get("key"))
        except Exception as e:
            logger.exception("Jira dispatch error: %s", e)

    def _map_to_jira_priority(self, severity: str) -> str:
        s = severity.lower()
        if s == "critical": return "Highest"
        if s == "high": return "High"
        if s == "medium": return "Medium"
        return "Low"
