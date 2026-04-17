"""AbuseIPDB API client — check IP reputation."""
from __future__ import annotations
import time
from typing import Any

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBClient:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.available = bool(api_key and _HTTPX_AVAILABLE)

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict[str, Any]:
        if not self.available:
            return {"error": "ABUSEIPDB_UNAVAILABLE", "reason": "No API key or httpx missing"}
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True}
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(f"{ABUSEIPDB_BASE}/check", headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json().get("data", {})
                return {
                    "ip": ip,
                    "confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "usage_type": data.get("usageType", ""),
                    "isp": data.get("isp", ""),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported": data.get("lastReportedAt", ""),
                }
        except Exception as e:
            return {"error": str(e), "ip": ip}
