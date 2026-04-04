"""
ai_triage.py — AI-Assisted Scoring and Risk Analysis

Responsibility:
  - Deep analysis of findings using Google Gemini LLM
  - Predictive exploitability and business impact (UGX)
  - Attack chain identification
  - Professional remediation guidance
"""

import logging
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

try:
    import google.generativeai as genai
    HAS_GOOGLE_GENAI = True
except ImportError:
    logger.warning("google-generativeai not installed. AI triage will be disabled.")
    HAS_GOOGLE_GENAI = False


@dataclass
class AITriageResult:
    predicted_exploitability: float = 0.0  # 0.0 to 1.0
    exploit_chain_potential: bool = False
    business_impact_score: float = 0.0
    suggested_priority: str = "medium"
    analysis_summary: str = ""
    financial_impact_estimate: float = 0.0  # In UGX
    smart_remediation: List[str] = field(default_factory=list)


class GeminiTriageProvider:
    """
    Interfaces with Google's Gemini LLM for expert-level triage.
    """
    def __init__(self, api_key: Optional[str] = None):
        if api_key and HAS_GOOGLE_GENAI:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-pro')
            self.enabled = True
        else:
            self.enabled = False

    async def analyze_finding(self, finding_data: Dict, target_context: Dict) -> Optional[Dict]:
        """
        Send finding context to Gemini for risk summary and remediation.
        """
        if not self.enabled:
            return None
            
        prompt = self._build_prompt(finding_data, target_context)
        
        try:
            # We use a blocking call here as the SDK doesn't natively support async yet
            # In a pro app we'd wrap this or use a thread pool
            response = self.model.generate_content(prompt)
            return self._parse_response(response.text)
        except Exception as e:
            logger.error("Gemini AI Analysis failed: %s", e)
            return None

    def _build_prompt(self, finding: Dict, context: Dict) -> str:
        return f"""
        You are a Senior Security Consultant at VulnScout Pro, specializing in the East African tech landscape.
        Analyze the following vulnerability finding and provide expert triage.

        FINDING DETAILS:
        - Type: {finding.get('vuln_type')}
        - Label: {finding.get('vuln_label')}
        - Severity: {finding.get('severity')}
        - URL: {finding.get('url')}
        - Parameter: {finding.get('parameter_name')}
        - Evidence Excerpt: {finding.get('evidence', {}).get('response', {}).get('body_excerpt', '')[:500]}

        TARGET CONTEXT:
        - Industry: {context.get('industry', 'general')}
        - Technology Stack: {finding.get('technology_context', [])}
        - Region: East Africa (Uganda/Kenya/Tanzania)

        TASK:
        1. Evaluate the real-world exploitability (0.0 to 1.0).
        2. Identify if this could be part of a larger exploit chain.
        3. Estimate business impact in Ugandan Shillings (UGX) considering the industry.
        4. Provide a professional, concise summary of the risk.
        5. Provide 3-5 specific remediation steps tailored to the technology stack.

        Respond ONLY in JSON format:
        {{
            "exploitability": 0.0-1.0,
            "chain_potential": true/false,
            "financial_impact_ugx": number,
            "risk_summary": "string",
            "smart_remediation": ["step1", "step2"]
        }}
        """

    def _parse_response(self, text: str) -> Optional[Dict]:
        try:
            # Clean up potential markdown formatting in LLM response
            clean_text = text.replace("```json", "").replace("```", "").strip()
            return json.loads(clean_text)
        except Exception:
            logger.warning("Failed to parse Gemini JSON response")
            return None


class AITriageEngine:
    """
    Central engine for AI-assisted vulnerability triage.
    """

    def __init__(self, gemini_api_key: Optional[str] = None) -> None:
        from config import get_config
        config = get_config()
        
        api_key = gemini_api_key or config.ai.gemini_api_key
        self.ai_provider = GeminiTriageProvider(api_key=api_key)

    async def triage(self, finding: Any, context: Dict) -> AITriageResult:
        """
        Perform AI-based triage for a single finding.
        """
        finding_dict = finding.to_dict() if hasattr(finding, "to_dict") else finding
        
        # Default fallback results
        res = AITriageResult(
            predicted_exploitability=0.5,
            analysis_summary="Automated heuristic triage.",
            financial_impact_estimate=500000.0 # 500k UGX base
        )

        if self.ai_provider.enabled:
            ai_data = await self.ai_provider.analyze_finding(finding_dict, context)
            if ai_data:
                res.predicted_exploitability = ai_data.get("exploitability", res.predicted_exploitability)
                res.exploit_chain_potential = ai_data.get("chain_potential", False)
                res.financial_impact_estimate = ai_data.get("financial_impact_ugx", res.financial_impact_estimate)
                res.analysis_summary = ai_data.get("risk_summary", res.analysis_summary)
                res.smart_remediation = ai_data.get("smart_remediation", [])
        
        # Calculate impact score (0-10) for UI
        res.business_impact_score = self._calculate_impact_score(res.financial_impact_estimate)
        res.suggested_priority = self._map_score_to_priority(res.business_impact_score)

        return res

    def _calculate_impact_score(self, ugx: float) -> float:
        # 10M UGX = 10.0 score
        score = ugx / 1_000_000
        return min(10.0, max(1.0, score))

    def _map_score_to_priority(self, score: float) -> str:
        if score >= 8.5: return "P0 - Emergency"
        if score >= 7.0: return "P1 - Critical"
        if score >= 4.0: return "P2 - High"
        return "P3 - Routine"
