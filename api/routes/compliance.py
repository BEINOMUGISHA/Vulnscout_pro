import logging
import json
import random
from typing import Dict, Any
from fastapi import APIRouter
from fastapi.responses import Response

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory compliance states
def generate_standards():
    return {
        "core": [
            {"id": "owasp-2021", "name": "OWASP Top 10 (2021)", "status": "PASS" if random.random() > 0.2 else "WARN", "score": random.randint(70, 100)},
            {"id": "cwe-25", "name": "CWE Top 25 Most Dangerous Software Weaknesses", "status": "WARN", "score": random.randint(60, 90)},
            {"id": "sans-v20", "name": "SANS Top 20 Security Controls", "status": "FAIL" if random.random() > 0.5 else "WARN", "score": random.randint(40, 80)},
            {"id": "auth-2fa", "name": "Multi-Factor Authentication (2FA) Alignment", "status": "PASS", "score": 95},
        ],
        "api": [
            {"id": "owasp-api", "name": "OWASP API Security Top 10", "status": "PASS", "score": random.randint(85, 100)},
            {"id": "rest-security", "name": "REST Security Best Practices", "status": "PASS", "score": random.randint(85, 100)},
        ],
        "global": [
            {"id": "iso-27001", "name": "ISO/IEC 27001", "status": "WARN", "score": random.randint(65, 95)},
            {"id": "nist-csf", "name": "NIST Cybersecurity Framework", "status": "PASS", "score": random.randint(90, 100)},
        ]
    }

_COMPLIANCE_DB = generate_standards()

@router.get("")
async def get_compliance():
    return {"status": "success", "standards": _COMPLIANCE_DB}

@router.post("/recalculate")
async def recalculate_compliance():
    global _COMPLIANCE_DB
    _COMPLIANCE_DB = generate_standards()
    return {"status": "success", "standards": _COMPLIANCE_DB}

@router.get("/export")
async def export_compliance():
    data = json.dumps(_COMPLIANCE_DB, indent=2)
    return Response(content=data, media_type="application/json", headers={"Content-Disposition": "attachment; filename=compliance_ledger.json"})
