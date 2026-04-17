"""Offline MITRE ATT&CK mapping — keyword-based TTP inference, no internet required."""
from __future__ import annotations
from typing import NamedTuple


class TTPMatch(NamedTuple):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float


# Curated keyword → TTP mapping (offense-focused, Windows-centric)
_TECHNIQUE_MAP: list[tuple[list[str], str, str, str]] = [
    # Initial Access
    (["phishing", "spearphish", "malicious attachment", "macro"], "T1566", "Phishing", "Initial Access"),
    (["exploit", "vulnerability", "cve", "rce", "zero-day"], "T1190", "Exploit Public-Facing Application", "Initial Access"),
    # Execution
    (["powershell", "encodedcommand", "-enc", "-e ", "iex", "invoke-expression"], "T1059.001", "PowerShell", "Execution"),
    (["cmd.exe", "command prompt", "cmd /c", "cmd /k"], "T1059.003", "Windows Command Shell", "Execution"),
    (["wscript", "cscript", "vbscript", ".vbs", ".js jscript"], "T1059.005", "Visual Basic", "Execution"),
    (["mshta", ".hta", "html application"], "T1218.005", "Mshta", "Defense Evasion"),
    (["rundll32", ".dll,"], "T1218.011", "Rundll32", "Defense Evasion"),
    (["regsvr32", "/s /u", "scrobj"], "T1218.010", "Regsvr32", "Defense Evasion"),
    (["wmic", "wmiprvse", "winmgmt"], "T1047", "Windows Management Instrumentation", "Execution"),
    (["scheduled task", "schtasks", "at.exe", "taskschd"], "T1053.005", "Scheduled Task", "Persistence"),
    # Persistence
    (["run key", "currentversion\\run", "runonce", "registry run"], "T1547.001", "Registry Run Keys", "Persistence"),
    (["service", "new-service", "sc create", "services.exe"], "T1543.003", "Windows Service", "Persistence"),
    (["startup folder", "start menu\\programs\\startup"], "T1547.001", "Startup Folder", "Persistence"),
    (["winlogon", "userinit", "shell value"], "T1547.004", "Winlogon Helper DLL", "Persistence"),
    # Privilege Escalation
    (["token impersonation", "seimpersonateprivilege", "juicy", "printspoofer"], "T1134", "Access Token Manipulation", "Privilege Escalation"),
    (["uac bypass", "fodhelper", "eventvwr", "sdclt"], "T1548.002", "Bypass UAC", "Privilege Escalation"),
    # Defense Evasion
    (["masquerad", "svchost_helper", "fake process", "process name"], "T1036", "Masquerading", "Defense Evasion"),
    (["timestomp", "timestomping", "si != fn", "created0x10", "created0x30"], "T1070.006", "Timestomp", "Defense Evasion"),
    (["delete logs", "wevtutil cl", "clear-eventlog", "event log"], "T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
    (["obfuscat", "base64", "xor encrypt", "encoded"], "T1027", "Obfuscated Files or Information", "Defense Evasion"),
    (["process inject", "dll inject", "createremotethread", "writeprocessmemory"], "T1055", "Process Injection", "Defense Evasion"),
    (["process hollow", "hollowing", "runpe", "unmap"], "T1055.012", "Process Hollowing", "Defense Evasion"),
    # Credential Access
    (["mimikatz", "sekurlsa", "hashdump", "lsass dump", "credential"], "T1003", "OS Credential Dumping", "Credential Access"),
    (["ntlm hash", "pass the hash", "pth"], "T1550.002", "Pass the Hash", "Lateral Movement"),
    (["keylog", "keystroke"], "T1056.001", "Keylogging", "Credential Access"),
    # Discovery
    (["net user", "net group", "whoami", "systeminfo", "ipconfig", "arp -a"], "T1082", "System Information Discovery", "Discovery"),
    (["nmap", "portscan", "port scan", "network scan"], "T1046", "Network Service Discovery", "Discovery"),
    (["tasklist", "process list", "ps aux"], "T1057", "Process Discovery", "Discovery"),
    # Lateral Movement
    (["psexec", "remote execution", "lateral"], "T1570", "Lateral Tool Transfer", "Lateral Movement"),
    (["rdp", "mstsc", "3389", "remote desktop"], "T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
    (["smb", "445", "net use", "\\\\"], "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    # Collection
    (["screenshot", "capture screen"], "T1113", "Screen Capture", "Collection"),
    (["keylog", "clipboard"], "T1115", "Clipboard Data", "Collection"),
    # Command and Control
    (["4444", "beacon", "c2", "command and control", "cobalt strike", "metasploit"], "T1071", "Application Layer Protocol", "Command and Control"),
    (["dns tunnel", "dns exfil", "iodine", "dnscat"], "T1071.004", "DNS", "Command and Control"),
    (["http tunnel", "https c2", "port 80", "port 443 c2"], "T1071.001", "Web Protocols", "Command and Control"),
    # Exfiltration
    (["exfil", "data theft", "upload", "ftp exfil"], "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    # Impact
    (["ransomware", "encrypt files", ".locked", ".encrypted"], "T1486", "Data Encrypted for Impact", "Impact"),
    (["wiper", "wipe disk", "mbr wipe"], "T1561", "Disk Wipe", "Impact"),
]


def map_to_ttps(text: str) -> list[TTPMatch]:
    text_lower = text.lower()
    matches: list[TTPMatch] = []
    seen: set[str] = set()
    for keywords, tid, name, tactic in _TECHNIQUE_MAP:
        if tid in seen:
            continue
        hit_count = sum(1 for kw in keywords if kw in text_lower)
        if hit_count > 0:
            confidence = min(1.0, 0.5 + (hit_count / len(keywords)) * 0.5)
            matches.append(TTPMatch(tid, name, tactic, round(confidence, 2)))
            seen.add(tid)
    return sorted(matches, key=lambda m: m.confidence, reverse=True)


def map_finding_to_ttps(finding: dict) -> list[dict]:
    text = " ".join([
        finding.get("description", ""),
        finding.get("raw_evidence_excerpt", ""),
        finding.get("title", ""),
        str(finding.get("mitre_hints", "")),
    ])
    ttps = map_to_ttps(text)
    return [{"technique_id": t.technique_id, "technique_name": t.technique_name,
             "tactic": t.tactic, "confidence": t.confidence} for t in ttps[:5]]
