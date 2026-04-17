"""
AbuseIPDB wrapper — checks IP addresses against abuse reports.
Provides confidence score (0-100) and number of reports.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Optional

import httpx
from pydantic import BaseModel

from core.audit import get_audit_logger
from mcp_server.config import config


class AbuseIPDBResult(BaseModel):
    ip_address: str
    confidence_score: int = 0   # 0-100, higher = more abusive
    total_reports: int = 0
    country_code: str = ""
    usage_type: str = ""
    isp: str = ""
    domain: str = ""
    is_tor: bool = False
    verdict: str = "UNKNOWN"  # MALICIOUS (>= 75), SUSPICIOUS (>= 25), CLEAN
    error: Optional[str] = None


_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
_cache: dict[str, AbuseIPDBResult] = {}
_last_call: float = 0.0


def check_ip(ip_address: str) -> AbuseIPDBResult:
    if not config.ABUSEIPDB_API_KEY:
        return AbuseIPDBResult(
            ip_address=ip_address,
            error="ABUSEIPDB_API_KEY not configured — enrichment skipped",
        )

    if ip_address in _cache:
        return _cache[ip_address]

    _rate_limit()
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"{_ABUSEIPDB_BASE}/check",
                headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""},
            )
        if resp.status_code != 200:
            result = AbuseIPDBResult(ip_address=ip_address, error=f"HTTP {resp.status_code}")
        else:
            result = _parse_response(ip_address, resp.json())
    except Exception as e:
        result = AbuseIPDBResult(ip_address=ip_address, error=str(e))

    _cache[ip_address] = result
    get_audit_logger().log_tool_execution(
        agent="enrichment",
        tool_name="abuseipdb",
        command=f"AbuseIPDB check: {ip_address}",
        output_hash=hashlib.sha256(result.model_dump_json().encode()).hexdigest()[:16],
    )
    return result


def _parse_response(ip: str, data: dict[str, Any]) -> AbuseIPDBResult:
    d = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    verdict = "CLEAN"
    if score >= 75:
        verdict = "MALICIOUS"
    elif score >= 25:
        verdict = "SUSPICIOUS"

    return AbuseIPDBResult(
        ip_address=ip,
        confidence_score=score,
        total_reports=d.get("totalReports", 0),
        country_code=d.get("countryCode", ""),
        usage_type=d.get("usageType", ""),
        isp=d.get("isp", ""),
        domain=d.get("domain", ""),
        is_tor=d.get("isTor", False),
        verdict=verdict,
    )


def _rate_limit() -> None:
    global _last_call
    elapsed = time.monotonic() - _last_call
    if elapsed < 1.1:
        time.sleep(1.1 - elapsed)
    _last_call = time.monotonic()
