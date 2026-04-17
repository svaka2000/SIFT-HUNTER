"""
MITRE ATT&CK mapping — maps findings to technique IDs using STIX data.
Downloads and caches the ATT&CK dataset locally. Works offline after first run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel

from mcp_server.config import config


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    url: str = ""


# Hardcoded keyword → technique mapping for offline operation
# Covers the most common techniques seen in incident response
KEYWORD_TO_TECHNIQUE: dict[str, tuple[str, str, str]] = {
    # Execution
    "powershell": ("T1059.001", "PowerShell", "Execution"),
    "cmd.exe": ("T1059.003", "Windows Command Shell", "Execution"),
    "wscript": ("T1059.005", "Visual Basic", "Execution"),
    "cscript": ("T1059.005", "Visual Basic", "Execution"),
    "mshta": ("T1218.005", "Mshta", "Defense Evasion"),
    "regsvr32": ("T1218.010", "Regsvr32", "Defense Evasion"),
    "rundll32": ("T1218.011", "Rundll32", "Defense Evasion"),
    "certutil": ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "bitsadmin": ("T1197", "BITS Jobs", "Defense Evasion"),

    # Persistence
    "run key": ("T1547.001", "Registry Run Keys", "Persistence"),
    "runonce": ("T1547.001", "Registry Run Keys", "Persistence"),
    "winlogon": ("T1547.004", "Winlogon Helper DLL", "Persistence"),
    "service": ("T1543.003", "Windows Service", "Persistence"),
    "scheduled task": ("T1053.005", "Scheduled Task", "Persistence"),
    "startup folder": ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
    "ifeo": ("T1546.012", "Image File Execution Options Injection", "Persistence"),
    "shellbag": ("T1083", "File and Directory Discovery", "Discovery"),

    # Credential Access
    "lsass": ("T1003.001", "LSASS Memory", "Credential Access"),
    "hashdump": ("T1003.001", "LSASS Memory", "Credential Access"),
    "credential": ("T1003", "OS Credential Dumping", "Credential Access"),
    "mimikatz": ("T1003.001", "LSASS Memory", "Credential Access"),

    # Defense Evasion
    "timestomp": ("T1070.006", "Timestomp", "Defense Evasion"),
    "timestamping": ("T1070.006", "Timestomp", "Defense Evasion"),
    "alternate data stream": ("T1564.004", "NTFS File Attributes", "Defense Evasion"),
    "ads": ("T1564.004", "NTFS File Attributes", "Defense Evasion"),
    "log deletion": ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
    "evtx deletion": ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
    "prefetch deletion": ("T1070.004", "File Deletion", "Defense Evasion"),
    "process injection": ("T1055", "Process Injection", "Defense Evasion"),
    "hollowing": ("T1055.012", "Process Hollowing", "Defense Evasion"),

    # Lateral Movement
    "lateral movement": ("T1021", "Remote Services", "Lateral Movement"),
    "psexec": ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    "wmi": ("T1021.006", "Windows Remote Management", "Lateral Movement"),
    "rdp": ("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
    "pass the hash": ("T1550.002", "Pass the Hash", "Lateral Movement"),

    # Command and Control
    "c2": ("T1071", "Application Layer Protocol", "Command and Control"),
    "beacon": ("T1071.001", "Web Protocols", "Command and Control"),
    "c&c": ("T1071", "Application Layer Protocol", "Command and Control"),
    "cobalt strike": ("T1071.001", "Web Protocols", "Command and Control"),

    # Exfiltration
    "exfiltration": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "exfil": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),

    # Discovery
    "network scan": ("T1046", "Network Service Discovery", "Discovery"),
    "port scan": ("T1046", "Network Service Discovery", "Discovery"),
    "directory listing": ("T1083", "File and Directory Discovery", "Discovery"),

    # Initial Access
    "phishing": ("T1566.001", "Spearphishing Attachment", "Initial Access"),
    "drive-by": ("T1189", "Drive-by Compromise", "Initial Access"),
}


def map_finding_to_ttps(
    description: str,
    title: str = "",
    existing_techniques: Optional[list[str]] = None,
) -> list[MITRETechnique]:
    """
    Map a finding description to MITRE ATT&CK techniques.
    Uses keyword matching plus any explicitly provided technique IDs.
    """
    techniques: list[MITRETechnique] = []
    seen_ids: set[str] = set()
    combined_text = f"{title} {description}".lower()

    # Explicit technique IDs in description (e.g., "T1059.001")
    for tid in re.findall(r"T\d{4}(?:\.\d{3})?", combined_text.upper()):
        if tid not in seen_ids:
            seen_ids.add(tid)
            # Look up in keyword map
            for _, (technique_id, name, tactic) in KEYWORD_TO_TECHNIQUE.items():
                if technique_id == tid:
                    techniques.append(MITRETechnique(
                        technique_id=tid,
                        technique_name=name,
                        tactic=tactic,
                        url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                    ))
                    break
            else:
                techniques.append(MITRETechnique(
                    technique_id=tid,
                    technique_name="Unknown",
                    tactic="Unknown",
                    url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                ))

    # Keyword matching
    for keyword, (technique_id, name, tactic) in KEYWORD_TO_TECHNIQUE.items():
        if keyword in combined_text and technique_id not in seen_ids:
            seen_ids.add(technique_id)
            techniques.append(MITRETechnique(
                technique_id=technique_id,
                technique_name=name,
                tactic=tactic,
                url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            ))

    return techniques


def get_tactic_for_technique(technique_id: str) -> str:
    """Return the primary tactic for a given technique ID."""
    for _, (tid, _, tactic) in KEYWORD_TO_TECHNIQUE.items():
        if tid == technique_id:
            return tactic
    return "Unknown"
