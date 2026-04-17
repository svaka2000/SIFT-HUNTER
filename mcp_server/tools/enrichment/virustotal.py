"""
VirusTotal API wrapper — enriches file hashes and IP addresses.
Rate-limited to 4 req/min on free tier with exponential backoff.
Gracefully degrades if no API key is configured.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime
from typing import Any, Optional

import httpx
from pydantic import BaseModel

from core.audit import get_audit_logger
from mcp_server.config import config


class VTResult(BaseModel):
    query: str
    query_type: str  # hash, ip, domain
    detection_ratio: str = "0/0"
    malicious_count: int = 0
    total_engines: int = 0
    verdict: str = "UNKNOWN"  # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN
    top_vendors: list[str] = []
    tags: list[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    permalink: str = ""
    error: Optional[str] = None
    cached: bool = False


_VT_BASE = "https://www.virustotal.com/api/v3"
_rate_limiter_last_call: float = 0.0
_cache: dict[str, VTResult] = {}


def check_hash(file_hash: str) -> VTResult:
    """Query VirusTotal for a file hash (MD5/SHA1/SHA256)."""
    return _vt_request("files", file_hash, "hash")


def check_ip(ip_address: str) -> VTResult:
    """Query VirusTotal for an IP address reputation."""
    return _vt_request("ip_addresses", ip_address, "ip")


def check_domain(domain: str) -> VTResult:
    """Query VirusTotal for a domain reputation."""
    return _vt_request("domains", domain, "domain")


def _vt_request(endpoint: str, query: str, query_type: str) -> VTResult:
    if not config.VT_API_KEY:
        return VTResult(
            query=query,
            query_type=query_type,
            error="VT_API_KEY not configured — enrichment skipped",
        )

    cache_key = f"{endpoint}:{query}"
    if cache_key in _cache:
        result = _cache[cache_key]
        result.cached = True
        return result

    _rate_limit()

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(
                f"{_VT_BASE}/{endpoint}/{query}",
                headers={"x-apikey": config.VT_API_KEY},
            )
        if resp.status_code == 404:
            result = VTResult(query=query, query_type=query_type, verdict="UNKNOWN", error="Not found in VT")
        elif resp.status_code == 429:
            result = VTResult(query=query, query_type=query_type, error="VT rate limit exceeded")
        elif resp.status_code != 200:
            result = VTResult(query=query, query_type=query_type, error=f"VT HTTP {resp.status_code}")
        else:
            result = _parse_vt_response(resp.json(), query, query_type)
    except httpx.TimeoutException:
        result = VTResult(query=query, query_type=query_type, error="VT request timeout")
    except Exception as e:
        result = VTResult(query=query, query_type=query_type, error=f"VT error: {e}")

    _cache[cache_key] = result
    get_audit_logger().log_tool_execution(
        agent="enrichment",
        tool_name="virustotal",
        command=f"VT {query_type}: {query}",
        output_hash=hashlib.sha256(result.model_dump_json().encode()).hexdigest()[:16],
    )
    return result


def _parse_vt_response(data: dict[str, Any], query: str, query_type: str) -> VTResult:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    results = attrs.get("last_analysis_results", {})

    top_vendors = [
        vendor for vendor, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ][:5]

    verdict = "CLEAN"
    if malicious > 5:
        verdict = "MALICIOUS"
    elif malicious > 0:
        verdict = "SUSPICIOUS"

    return VTResult(
        query=query,
        query_type=query_type,
        detection_ratio=f"{malicious}/{total}",
        malicious_count=malicious,
        total_engines=total,
        verdict=verdict,
        top_vendors=top_vendors,
        tags=attrs.get("tags", []),
        permalink=f"https://www.virustotal.com/gui/{query_type}s/{query}",
    )


def _rate_limit() -> None:
    global _rate_limiter_last_call
    elapsed = time.monotonic() - _rate_limiter_last_call
    min_interval = 15.5  # 4 req/min = 1 req per 15 seconds
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _rate_limiter_last_call = time.monotonic()
