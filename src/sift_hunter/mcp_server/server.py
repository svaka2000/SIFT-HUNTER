"""FastMCP server entry point — registers all forensic tools as typed MCP functions."""
from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from sift_hunter.config import config
from sift_hunter.core.audit import get_audit_logger
from sift_hunter.mcp_server.security.command_sanitizer import validate_command
from sift_hunter.core.exceptions import SecurityViolation


def create_server() -> FastMCP:
    """Build and return the configured FastMCP server."""
    server = FastMCP("sift-hunter")
    audit = get_audit_logger(config.AUDIT_LOG_PATH)

    @server.tool()
    def parse_mft(mft_path: str, output_dir: str = "/tmp/sift-output") -> dict:
        """Parse an MFT ($MFT) file and return structured entries with timestomping detection."""
        from sift_hunter.mcp_server.tools.disk.mft import MFTTool
        tool = MFTTool()
        return tool.analyze(mft_path, output_dir)

    @server.tool()
    def parse_prefetch(prefetch_path: str, output_dir: str = "/tmp/sift-output") -> dict:
        """Parse Prefetch files to recover execution history."""
        from sift_hunter.mcp_server.tools.disk.prefetch import PrefetchTool
        tool = PrefetchTool()
        return tool.analyze(prefetch_path, output_dir)

    @server.tool()
    def parse_amcache(amcache_path: str, output_dir: str = "/tmp/sift-output") -> dict:
        """Parse Amcache.hve for program installation history."""
        from sift_hunter.mcp_server.tools.disk.amcache import AmcacheTool
        tool = AmcacheTool()
        return tool.analyze(amcache_path, output_dir)

    @server.tool()
    def parse_registry(hive_path: str, hive_type: str = "ntuser", output_dir: str = "/tmp/sift-output") -> dict:
        """Parse a registry hive for persistence mechanisms and user activity."""
        from sift_hunter.mcp_server.tools.disk.registry import RegistryTool
        tool = RegistryTool()
        return tool.analyze(hive_path, hive_type, output_dir)

    @server.tool()
    def parse_shellbags(hive_path: str, output_dir: str = "/tmp/sift-output") -> dict:
        """Parse ShellBags from a registry hive for folder navigation history."""
        from sift_hunter.mcp_server.tools.disk.shellbags import ShellbagTool
        tool = ShellbagTool()
        return tool.analyze(hive_path, output_dir)

    @server.tool()
    def parse_usn_journal(usn_path: str, output_dir: str = "/tmp/sift-output") -> dict:
        """Parse the USN Journal ($UsnJrnl:$J) for file system activity."""
        from sift_hunter.mcp_server.tools.disk.usnjrnl import USNJournalTool
        tool = USNJournalTool()
        return tool.analyze(usn_path, output_dir)

    @server.tool()
    def run_volatility(memory_path: str, plugin: str, output_dir: str = "/tmp/sift-output") -> dict:
        """Run a Volatility3 plugin against a memory capture."""
        from sift_hunter.mcp_server.tools.memory.volatility import Volatility3Tool
        tool = Volatility3Tool()
        return tool.run_plugin(memory_path, plugin, output_dir)

    @server.tool()
    def list_processes(memory_path: str) -> dict:
        """List processes from a memory capture using Volatility3 pslist."""
        from sift_hunter.mcp_server.tools.memory.processes import ProcessTool
        tool = ProcessTool()
        return tool.list_processes(memory_path)

    @server.tool()
    def list_connections(memory_path: str) -> dict:
        """List network connections from a memory capture using netscan."""
        from sift_hunter.mcp_server.tools.memory.network import NetworkTool
        tool = NetworkTool()
        return tool.list_connections(memory_path)

    @server.tool()
    def check_hash(file_hash: str) -> dict:
        """Check a file hash against VirusTotal (requires VT_API_KEY)."""
        from sift_hunter.mcp_server.tools.enrichment.virustotal import VTClient
        client = VTClient()
        return client.check_hash(file_hash)

    @server.tool()
    def check_ip(ip_address: str) -> dict:
        """Check an IP address against AbuseIPDB (requires ABUSEIPDB_API_KEY)."""
        from sift_hunter.mcp_server.tools.enrichment.abuseipdb import AbuseIPDBClient
        client = AbuseIPDBClient()
        return client.check_ip(ip_address)

    @server.tool()
    def security_check(command: str) -> dict:
        """Test whether a command would be allowed by the security layer."""
        parts = command.split()
        if not parts:
            return {"allowed": False, "reason": "Empty command"}
        try:
            binary, args = validate_command(parts[0], parts[1:])
            return {"allowed": True, "resolved_binary": binary, "safe_args": args}
        except SecurityViolation as e:
            return {"allowed": False, "reason": str(e)}

    @server.tool()
    def get_available_tools() -> dict:
        """List all forensic tools and their installation status."""
        from sift_hunter.mcp_server.registry import get_available_tools as _get
        return {"tools": _get()}

    return server
