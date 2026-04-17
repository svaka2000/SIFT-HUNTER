"""Credential extraction — wraps Volatility3 hashdump, cachedump, lsadump."""
from __future__ import annotations
import re
from typing import Any

from sift_hunter.mcp_server.tools.memory.volatility import VolatilityTool


class CredentialsTool(VolatilityTool):
    tool_name = "credentials_extractor"
    description = "Extract credential artifacts from memory using Volatility3 hashdump/cachedump"

    def extract_hashes(self, memory_image: str) -> dict[str, Any]:
        return self.run_plugin(memory_image, "windows.hashdump.Hashdump")

    def extract_cached_creds(self, memory_image: str) -> dict[str, Any]:
        return self.run_plugin(memory_image, "windows.cachedump.Cachedump")

    def extract_lsa_secrets(self, memory_image: str) -> dict[str, Any]:
        return self.run_plugin(memory_image, "windows.lsadump.Lsadump")

    def parse_hashes(self, rows: list[dict]) -> list[dict]:
        hashes = []
        for row in rows:
            username = row.get("User") or row.get("Username") or ""
            ntlm = row.get("NT") or row.get("NTLM") or row.get("Hash") or ""
            lm = row.get("LM") or ""
            if username:
                entry = {"username": username, "ntlm_hash": ntlm, "lm_hash": lm}
                blank_ntlm = "31d6cfe0d16ae931b73c59d7e0c089c0"
                if ntlm.lower() == blank_ntlm:
                    entry["note"] = "blank_password"
                hashes.append(entry)
        return hashes

    def find_privileged_accounts(self, hash_rows: list[dict]) -> list[dict]:
        privileged = []
        for row in hash_rows:
            username = (row.get("User") or row.get("Username") or "").lower()
            if any(a in username for a in ["admin", "administrator", "domain admin", "da"]):
                privileged.append({"type": "PRIVILEGED_ACCOUNT", "username": username, "row": row})
        return privileged
