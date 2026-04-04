import pytest
import asyncio
import time
from unittest.mock import MagicMock, AsyncMock
from core.detection.sqli import SQLiDetector
from core.scanner.injector import Injector, InjectionResponse
from core.scanner.crawler import CrawlResult, CrawlParameter

@pytest.mark.asyncio
async def test_sqli_baseline_aware_timing():
    """Verify that SQLi detector uses baseline to avoid false positives from lag."""
    detector = SQLiDetector()
    injector = MagicMock(spec=Injector)
    
    state = {
        "call_count": 0,
        "current_req_payload": ""
    }
    
    # We use a base time that is large like real monotonic()
    base_time = time.monotonic()
    
    def mock_monotonic():
        state["call_count"] += 1
        if "SLEEP" in state["current_req_payload"] or "WAITFOR" in state["current_req_payload"]:
            # Start/End calls for payload test
            if state["call_count"] % 2 == 0:
                return base_time + 7.0 # 7s total from start
            return base_time + 0.0 # Reset to base_time for start
        
        return base_time + (state["call_count"] * 0.1)

    async def side_effect(req):
        state["current_req_payload"] = req.payload
        await asyncio.sleep(0.01)
        return InjectionResponse(
            request_id=req.request_id,
            url=req.url,
            method=req.method,
            parameter_name=req.parameter_name,
            payload=req.payload,
            encoding=req.encoding.value,
            status_code=200,
            body="Normal"
        )
            
    injector.inject = AsyncMock(side_effect=side_effect)
    
    param = CrawlParameter(name="id", value="1", location="query")
    crawl_result = CrawlResult(url="http://example.ug/api", method="GET", parameters=[param])
    
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(time, "monotonic", mock_monotonic)
        findings = await detector.detect(None, crawl_result, injector)
        
    assert len(findings) > 0
    # Find a blind hit
    blind_hits = [f for f in findings if "Response delayed" in f.evidence.response_body_excerpt]
    assert len(blind_hits) > 0

@pytest.mark.asyncio
async def test_sqli_boolean_differential():
    """Verify that Boolean SQLi uses differential analysis (TRUE vs FALSE)."""
    detector = SQLiDetector()
    injector = MagicMock(spec=Injector)
    
    async def side_effect(req):
        body = "Welcome! Results: " + "A"*500
        if "1=2" in req.payload:
            body = "Welcome! Results: " + "B"*50
            
        return InjectionResponse(
            request_id=req.request_id,
            url=req.url,
            method=req.method,
            parameter_name=req.parameter_name,
            payload=req.payload,
            encoding=req.encoding.value,
            status_code=200,
            body=body
        )
            
    injector.inject = AsyncMock(side_effect=side_effect)
    
    param = CrawlParameter(name="id", value="1", location="query")
    crawl_result = CrawlResult(url="http://example.ug/api", method="GET", parameters=[param])
    
    findings = await detector.detect(None, crawl_result, injector)
    
    # Should find a Boolean hit
    assert any(f.vuln_type == "sqli" for f in findings)
    hit = [f for f in findings if f.vuln_type == "sqli"][0]
    assert "Boolean Differential" in hit.evidence.response_body_excerpt
