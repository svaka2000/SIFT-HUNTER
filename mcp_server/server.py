"""
SIFT-HUNTER MCP Server entry point.
Registers all forensic tools as typed MCP functions with architectural security enforcement.
Every call is audit-logged. No destructive commands. No path traversal. No network exfiltration.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from core.audit import get_audit_logger, reset_audit_logger
from core.evidence_integrity import ingest_evidence
from mcp_server.config import config
from mcp_server.security import check_command_safety
from mcp_server.validators.path_validator import SecurityError

# Tool imports
from mcp_server.tools.disk.timeline import TimelineTool
from mcp_server.tools.disk.mft import MFTTool
from mcp_server.tools.disk.prefetch import PrefetchTool
from mcp_server.tools.disk.amcache import AmcacheTool
from mcp_server.tools.disk.registry import RegistryTool
from mcp_server.tools.disk.usnjrnl import USNJournalTool
from mcp_server.tools.disk.shellbags import ShellbagTool
from mcp_server.tools.memory.processes import ProcessAnalysisTool
from mcp_server.tools.memory.network import NetworkAnalysisTool
from mcp_server.tools.memory.credentials import CredentialsTool
from mcp_server.tools.memory.volatility import Volatility3Tool
from mcp_server.tools.enrichment import virustotal, abuseipdb, mitre
from mcp_server.tools.reporting.markdown_report import generate_markdown_report
from mcp_server.tools.reporting.timeline_viz import generate_ascii_timeline


# Initialize
config.ensure_output_dir()
_warnings = config.validate()
_audit = reset_audit_logger(config.AUDIT_LOG_PATH)

# Instantiate tool objects (shared across all MCP calls)
_timeline_tool = TimelineTool()
_mft_tool = MFTTool()
_prefetch_tool = PrefetchTool()
_amcache_tool = AmcacheTool()
_registry_tool = RegistryTool()
_usnjrnl_tool = USNJournalTool()
_shellbag_tool = ShellbagTool()
_process_tool = ProcessAnalysisTool()
_network_tool = NetworkAnalysisTool()
_cred_tool = CredentialsTool()
_vol_tool = Volatility3Tool()

# Create the MCP server
mcp = FastMCP(
    name="sift-hunter",
    instructions=(
        "SIFT-HUNTER forensic analysis server. "
        "All tools are READ-ONLY. No destructive commands are available. "
        "All calls are audit-logged. Provide evidence paths within configured evidence roots."
    ),
)


# ── Evidence Management ──────────────────────────────────────────────────────

@mcp.tool()
def ingest_evidence_file(evidence_path: str) -> dict:
    """
    Ingest an evidence file: detect type, compute SHA256, begin chain of custody.
    Must be called before analysis to establish integrity baseline.
    """
    try:
        ev = ingest_evidence(evidence_path, agent="mcp_server")
        _audit.log_agent_transition("mcp_server", "EVIDENCE_INGESTED",
                                    reasoning=f"Ingested {evidence_path}, hash={ev.hash_sha256[:16]}")
        return ev.model_dump(mode="json")
    except (FileNotFoundError, SecurityError) as e:
        return {"error": str(e)}


@mcp.tool()
def get_audit_trail(finding_id: str) -> str:
    """
    Return the full evidence chain for a specific finding ID.
    Use this to trace exactly which tool outputs support each finding.
    """
    return _audit.print_finding_chain(finding_id)


@mcp.tool()
def export_audit_log() -> list[dict]:
    """Export the complete audit log as a list of structured JSON entries."""
    return _audit.export_json()


# ── Disk Forensics ───────────────────────────────────────────────────────────

@mcp.tool()
def create_timeline(image_path: str) -> dict:
    """
    Generate a super-timeline from a disk image using log2timeline/plaso.
    Returns structured timeline events. Image must be in evidence root.
    """
    te, result = _timeline_tool.create_timeline(image_path, agent="mcp_disk")
    return {
        "tool_execution_id": te.id,
        "exit_code": te.exit_code,
        "storage_file": result.storage_file,
        "total_events": result.total_events,
        "sample_events": [e.model_dump(mode="json") for e in result.events[:50]],
        "error": result.error,
    }


@mcp.tool()
def filter_timeline(csv_path: str, keyword: Optional[str] = None,
                    start_time: Optional[str] = None, end_time: Optional[str] = None) -> dict:
    """Filter an existing timeline CSV by keyword, start_time, or end_time."""
    result = _timeline_tool.filter_timeline(csv_path, keyword, start_time, end_time)
    return result.model_dump(mode="json")


@mcp.tool()
def parse_mft(mft_path: str) -> dict:
    """
    Parse the NTFS MFT to reveal file creation/modification history and timestomping.
    Returns entries with SI vs FN timestamp comparison for anti-forensics detection.
    """
    te, result = _mft_tool.parse_mft(mft_path, agent="mcp_disk")
    suspicious = _mft_tool.find_suspicious_entries(result)
    return {
        "tool_execution_id": te.id,
        "total_entries": result.total_entries,
        "suspicious_count": len(suspicious),
        "suspicious_entries": [
            {"filename": s.entry.fullpath, "reason": s.reason, "severity": s.severity}
            for s in suspicious[:20]
        ],
        "sample_entries": [e.model_dump(mode="json") for e in result.entries[:20]],
        "error": result.error,
    }


@mcp.tool()
def parse_prefetch(prefetch_dir: str) -> dict:
    """
    Parse Windows Prefetch files to reveal program execution history.
    Returns execution timeline with suspicious executables flagged.
    """
    te, entries = _prefetch_tool.parse_prefetch(prefetch_dir, agent="mcp_disk")
    timeline = _prefetch_tool.find_execution_artifacts(entries)
    return {
        "tool_execution_id": te.id,
        "total_entries": len(entries),
        "suspicious_executables": timeline.suspicious_executables,
        "execution_timeline": timeline.events[:50],
        "all_entries": [e.model_dump(mode="json") for e in entries[:30]],
    }


@mcp.tool()
def parse_amcache(amcache_path: str) -> dict:
    """
    Parse the Amcache.hve registry hive for program installation and execution artifacts.
    Returns SHA1 hashes suitable for VirusTotal lookups.
    """
    te, result = _amcache_tool.parse_amcache(amcache_path, agent="mcp_disk")
    hashes = _amcache_tool.get_hashes_for_lookup(result)
    return {
        "tool_execution_id": te.id,
        "total_programs": result.total_count,
        "hashes_for_lookup": hashes[:50],
        "programs": [p.model_dump(mode="json") for p in result.programs[:30]],
        "error": result.error,
    }


@mcp.tool()
def parse_registry(hive_path: str, hive_type: str = "software") -> dict:
    """
    Parse a Windows registry hive for persistence mechanisms and user activity.
    hive_type: software, system, ntuser, security, sam
    """
    te, result = _registry_tool.parse_registry_hive(hive_path, hive_type, agent="mcp_disk")
    return {
        "tool_execution_id": te.id,
        "hive_type": hive_type,
        "persistence_entries": [p.model_dump(mode="json") for p in result.persistence_entries],
        "total_values": len(result.values),
        "error": result.error,
    }


@mcp.tool()
def parse_usn_journal(usn_path: str) -> dict:
    """
    Parse the NTFS USN Journal for file system activity including deletions.
    Critical for detecting anti-forensics: log deletion, malware self-deletion.
    """
    te, result = _usnjrnl_tool.parse_usn_journal(usn_path, agent="mcp_disk")
    deletions = _usnjrnl_tool.find_file_deletions(result)
    return {
        "tool_execution_id": te.id,
        "total_records": result.total_records,
        "deletion_events": [d.model_dump(mode="json") for d in deletions[:30]],
        "error": result.error,
    }


@mcp.tool()
def parse_shellbags(hive_path: str) -> dict:
    """
    Parse ShellBags from registry hive to reveal attacker folder navigation history.
    Shows which directories were accessed, even if files are deleted.
    """
    te, entries = _shellbag_tool.parse_shellbags(hive_path, agent="mcp_disk")
    suspicious = _shellbag_tool.find_suspicious_navigation(entries)
    return {
        "tool_execution_id": te.id,
        "total_entries": len(entries),
        "suspicious_navigation": [e.model_dump(mode="json") for e in suspicious],
        "sample_entries": [e.model_dump(mode="json") for e in entries[:30]],
    }


# ── Memory Forensics ─────────────────────────────────────────────────────────

@mcp.tool()
def list_processes(memory_image: str) -> dict:
    """
    List all processes from a memory capture using Volatility3 pslist.
    Returns process tree with suspicious processes flagged.
    """
    te, processes = _process_tool.list_processes(memory_image, agent="mcp_memory")
    suspicious = _process_tool.find_suspicious_processes(processes)
    return {
        "tool_execution_id": te.id,
        "total_processes": len(processes),
        "suspicious_count": len(suspicious),
        "suspicious_processes": [
            {
                "pid": s.process.pid,
                "name": s.process.name,
                "ppid": s.process.ppid,
                "reason": s.reason,
                "severity": s.severity,
                "mitre": s.mitre_technique,
            }
            for s in suspicious
        ],
        "all_processes": [
            {
                "pid": p.pid, "name": p.name, "ppid": p.ppid,
                "create_time": p.create_time.isoformat() if p.create_time else None,
            }
            for p in processes[:50]
        ],
    }


@mcp.tool()
def get_cmdlines(memory_image: str) -> dict:
    """
    Extract process command lines from memory.
    Flags obfuscated PowerShell, encoded commands, and LOLBin abuse.
    """
    te, cmdlines = _process_tool.get_process_cmdlines(memory_image, agent="mcp_memory")
    suspicious = [c for c in cmdlines if c.suspicious]
    return {
        "tool_execution_id": te.id,
        "total": len(cmdlines),
        "suspicious": [c.model_dump(mode="json") for c in suspicious],
        "all": [c.model_dump(mode="json") for c in cmdlines[:50]],
    }


@mcp.tool()
def list_network_connections(memory_image: str) -> dict:
    """
    List network connections from memory using Volatility3 netscan.
    Returns connections with C2/lateral movement indicators flagged.
    """
    te, connections = _network_tool.list_connections(memory_image, agent="mcp_memory")
    suspicious = _network_tool.find_suspicious_connections(connections)
    return {
        "tool_execution_id": te.id,
        "total_connections": len(connections),
        "suspicious_count": len(suspicious),
        "suspicious_connections": [
            {
                "pid": s.connection.pid,
                "process": s.connection.process_name,
                "local": f"{s.connection.local_addr}:{s.connection.local_port}",
                "foreign": f"{s.connection.foreign_addr}:{s.connection.foreign_port}",
                "reason": s.reason,
                "severity": s.severity,
                "ioc_type": s.ioc_type,
            }
            for s in suspicious
        ],
        "all_connections": [c.model_dump(mode="json") for c in connections[:50]],
    }


@mcp.tool()
def extract_credentials(memory_image: str) -> dict:
    """
    Extract credential hashes from memory using Volatility3 hashdump.
    Returns account list with privileged account flags. Hashes shown for IR use.
    """
    te, result = _cred_tool.full_credential_assessment(memory_image, agent="mcp_memory")
    return {
        "tool_execution_id": te.id,
        "accounts_found": result.accounts_found,
        "privileged_accounts": result.privileged_accounts,
        "hashes": [h.model_dump(mode="json") for h in result.hashes],
        "cached_credentials_count": len(result.cached_creds),
        "error": result.error,
    }


@mcp.tool()
def run_volatility_plugin(memory_image: str, plugin_name: str, extra_args: Optional[list[str]] = None) -> dict:
    """
    Run any Volatility3 plugin against a memory image.
    plugin_name: e.g., 'windows.malfind.Malfind', 'windows.handles.Handles'
    """
    te, result = _vol_tool.run_plugin(
        memory_image, plugin_name, extra_args, agent="mcp_memory"
    )
    return {
        "tool_execution_id": te.id,
        "plugin": plugin_name,
        "columns": result.columns,
        "row_count": len(result.rows),
        "rows": result.rows[:100],
        "error": result.error,
    }


# ── Threat Intelligence ──────────────────────────────────────────────────────

@mcp.tool()
def vt_check_hash(file_hash: str) -> dict:
    """Query VirusTotal for a file hash. Returns detection ratio and verdict."""
    result = virustotal.check_hash(file_hash)
    return result.model_dump(mode="json")


@mcp.tool()
def vt_check_ip(ip_address: str) -> dict:
    """Query VirusTotal for an IP address reputation."""
    result = virustotal.check_ip(ip_address)
    return result.model_dump(mode="json")


@mcp.tool()
def abuseipdb_check(ip_address: str) -> dict:
    """Check an IP against AbuseIPDB. Returns confidence score (0-100)."""
    result = abuseipdb.check_ip(ip_address)
    return result.model_dump(mode="json")


@mcp.tool()
def map_to_mitre(description: str, title: str = "") -> dict:
    """
    Map a finding description to MITRE ATT&CK technique IDs.
    Returns technique IDs, names, and tactics.
    """
    techniques = mitre.map_finding_to_ttps(description, title)
    return {"techniques": [t.model_dump(mode="json") for t in techniques]}


# ── Security Boundary Test ───────────────────────────────────────────────────

@mcp.tool()
def security_check(command: str) -> dict:
    """
    Test whether a command would be blocked by the security layer.
    USE THIS TO DEMONSTRATE ARCHITECTURAL GUARDRAILS IN THE DEMO.
    Returns blocked=True with reason for any destructive/network command.
    """
    try:
        check_command_safety(command)
        return {"blocked": False, "command": command, "message": "Command would be allowed."}
    except SecurityError as e:
        return {"blocked": True, "command": command, "reason": str(e)}


# ── Server Entry Point ───────────────────────────────────────────────────────

def main():
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    console.print(Panel.fit(
        "[bold green]SIFT-HUNTER MCP Server[/]\n"
        "[dim]Self-correcting Intelligent Forensic Triage & Hunt[/]\n"
        f"[yellow]Evidence Roots:[/] {config.EVIDENCE_ROOTS}\n"
        f"[yellow]Audit Log:[/] {config.AUDIT_LOG_PATH}",
        title="Starting",
        border_style="green",
    ))

    if _warnings:
        for w in _warnings:
            console.print(f"[yellow]⚠ {w}[/]")

    mcp.run()


if __name__ == "__main__":
    main()
