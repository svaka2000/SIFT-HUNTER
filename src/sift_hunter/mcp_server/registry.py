"""Central registry of all available forensic tools with availability checking."""
from __future__ import annotations

import shutil

TOOL_REGISTRY: dict[str, dict] = {
    "parse_mft": {
        "description": "Parse MFT ($MFT) — entries with timestamps, timestomping detection",
        "category": "disk",
        "binary": "MFTECmd",
    },
    "parse_prefetch": {
        "description": "Parse Prefetch files — execution history",
        "category": "disk",
        "binary": "PECmd",
    },
    "parse_amcache": {
        "description": "Parse Amcache.hve — program installation with SHA1 hashes",
        "category": "disk",
        "binary": "AmcacheParser",
    },
    "parse_registry": {
        "description": "Parse registry hive — persistence, user activity",
        "category": "disk",
        "binary": "RECmd",
    },
    "parse_shellbags": {
        "description": "Parse ShellBags — folder navigation history",
        "category": "disk",
        "binary": "SBECmd",
    },
    "parse_usn_journal": {
        "description": "Parse USN Journal ($UsnJrnl:$J) — file system activity",
        "category": "disk",
        "binary": "MFTECmd",
    },
    "run_timeline": {
        "description": "Build super-timeline via log2timeline/psort",
        "category": "disk",
        "binary": "log2timeline.py",
    },
    "run_volatility": {
        "description": "Run any Volatility3 plugin against a memory capture",
        "category": "memory",
        "binary": "vol",
    },
    "list_processes": {
        "description": "List processes from memory (pslist + pstree)",
        "category": "memory",
        "binary": "vol",
    },
    "list_connections": {
        "description": "List network connections from memory (netscan)",
        "category": "memory",
        "binary": "vol",
    },
    "run_malfind": {
        "description": "Detect code injection via malfind",
        "category": "memory",
        "binary": "vol",
    },
    "extract_hashes": {
        "description": "Extract NTLM hashes via hashdump",
        "category": "memory",
        "binary": "vol",
    },
    "check_hash": {
        "description": "VirusTotal file hash lookup",
        "category": "enrichment",
        "binary": None,
    },
    "check_ip": {
        "description": "AbuseIPDB IP reputation check",
        "category": "enrichment",
        "binary": None,
    },
    "map_mitre": {
        "description": "Map finding to MITRE ATT&CK techniques (offline)",
        "category": "enrichment",
        "binary": None,
    },
}


def get_available_tools() -> list[dict]:
    """Return all tools with their availability status."""
    result = []
    for name, info in TOOL_REGISTRY.items():
        binary = info.get("binary")
        available = binary is None or bool(shutil.which(binary))
        result.append({
            "name": name,
            "description": info["description"],
            "category": info["category"],
            "binary": binary,
            "available": available,
        })
    return result
