"""VirusTotal API client - check hashes, IPs, domains. Rate-limited to 4 req/min."""
from __future__ import annotations
import time
import hashlib
from typing import Any

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


VT_BASE = "https://www.virustotal.com/api/v3"
_last_call_times: list[float] = []
_RATE_LIMIT = 4
_RATE_WINDOW = 60.0


def _rate_limit() -> None:
    now = time.monotonic()
    recent = [t for t in _last_call_times if now - t < _RATE_WINDOW]
    if len(recent) >= _RATE_LIMIT:
        sleep_for = _RATE_WINDOW - (now - recent[0]) + 0.1
        if sleep_for > 0:
            time.sleep(sleep_for)
    _last_call_times.clear()
    _last_call_times.extend(recent)
    _last_call_times.append(time.monotonic())


class VirusTotalClient:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.available = bool(api_key and _HTTPX_AVAILABLE)

    def _get(self, endpoint: str) -> dict[str, Any]:
        if not self.available:
            return {"error": "VT_UNAVAILABLE", "reason": "No API key or httpx missing"}
        _rate_limit()
        headers = {"x-apikey": self.api_key, "accept": "application/json"}
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.get(f"{VT_BASE}/{endpoint}", headers=headers)
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def check_hash(self, file_hash: str) -> dict[str, Any]:
        data = self._get(f"files/{file_hash}")
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "hash": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()),
            "tags": attrs.get("tags", []),
            "name": attrs.get("meaningful_name", ""),
            "type": attrs.get("type_description", ""),
        }

    def check_ip(self, ip: str) -> dict[str, Any]:
        data = self._get(f"ip_addresses/{ip}")
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "country": attrs.get("country", ""),
            "asn": attrs.get("asn", ""),
            "owner": attrs.get("as_owner", ""),
        }

    def check_domain(self, domain: str) -> dict[str, Any]:
        data = self._get(f"domains/{domain}")
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "categories": attrs.get("categories", {}),
        }
