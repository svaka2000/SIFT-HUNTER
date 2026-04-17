"""
Credential extraction via Volatility3 hashdump/lsadump.
Reveals attacker credential access and lateral movement capabilities.
All output is handled as potential PII — redacted in reports by default.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

from core.models import ToolExecution
from mcp_server.tools.memory.volatility import Volatility3Tool


class CredentialHash(BaseModel):
    username: str = ""
    rid: str = ""
    lm_hash: str = ""
    nt_hash: str = ""
    is_blank_password: bool = False
    is_empty_lm: bool = False
    raw: dict[str, Any] = {}


class CachedCredential(BaseModel):
    username: str = ""
    domain: str = ""
    hash_value: str = ""
    last_written: str = ""
    raw: dict[str, Any] = {}


class LSASecret(BaseModel):
    secret_name: str = ""
    secret_value: str = ""  # Shown only in full audit; redacted in reports


class CredentialResult(BaseModel):
    hashes: list[CredentialHash] = []
    cached_creds: list[CachedCredential] = []
    lsa_secrets: list[LSASecret] = []
    accounts_found: int = 0
    privileged_accounts: list[str] = []
    error: Optional[str] = None


# Known blank/empty hash values
BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"
EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


class CredentialsTool(Volatility3Tool):
    tool_name = "vol3-credentials"

    def extract_hashes(
        self,
        memory_image: str,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, list[CredentialHash]]:
        te, result = self.run_plugin(
            memory_image,
            "windows.hashdump.Hashdump",
            agent=agent,
            phase=phase,
            iteration=iteration,
        )
        hashes = _rows_to_hashes(result.rows)
        return te, hashes

    def find_cached_credentials(
        self,
        memory_image: str,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, list[CachedCredential]]:
        te, result = self.run_plugin(
            memory_image,
            "windows.cachedump.Cachedump",
            agent=agent,
            phase=phase,
            iteration=iteration,
        )
        cached: list[CachedCredential] = []
        for row in result.rows:
            cached.append(CachedCredential(
                username=str(row.get("Username", "")),
                domain=str(row.get("Domain", "")),
                hash_value=str(row.get("Hash", row.get("NTHash", ""))),
                raw=row,
            ))
        return te, cached

    def full_credential_assessment(
        self,
        memory_image: str,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, CredentialResult]:
        te_hash, hashes = self.extract_hashes(memory_image, agent, phase, iteration)
        _, cached = self.find_cached_credentials(memory_image, agent, phase, iteration)

        privileged = [
            h.username for h in hashes
            if h.username.lower() in ["administrator", "admin", "system", "root"]
            or h.username.endswith("$")  # Machine accounts
        ]

        result = CredentialResult(
            hashes=hashes,
            cached_creds=cached,
            accounts_found=len(hashes),
            privileged_accounts=privileged,
        )
        return te_hash, result


def _rows_to_hashes(rows: list[dict[str, Any]]) -> list[CredentialHash]:
    hashes: list[CredentialHash] = []
    for row in rows:
        lm = str(row.get("LMHash", row.get("lm_hash", "")))
        nt = str(row.get("NTHash", row.get("nt_hash", row.get("NThash", ""))))
        hashes.append(CredentialHash(
            username=str(row.get("Username", row.get("username", ""))),
            rid=str(row.get("RID", row.get("rid", ""))),
            lm_hash=lm,
            nt_hash=nt,
            is_blank_password=nt.lower() == EMPTY_NT,
            is_empty_lm=lm.lower() == BLANK_LM,
            raw=row,
        ))
    return hashes
