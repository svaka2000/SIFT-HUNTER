"""Network connection analysis — wraps Volatility3 netscan/netstat."""
from __future__ import annotations
import ipaddress
from typing import Any

from sift_hunter.mcp_server.tools.memory.volatility import VolatilityTool


C2_PORTS = {4444, 4445, 1337, 31337, 8888, 9999, 6666, 1234, 5555}
SUSPICIOUS_PROCS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "regsvr32.exe", "rundll32.exe", "certutil.exe"}


def _is_external(ip: str) -> bool:
    """Returns True for externally routable IPs (not private, not loopback, not link-local)."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified)
    except ValueError:
        return False


class NetworkTool(VolatilityTool):
    tool_name = "network_analyzer"
    description = "Analyze network connections in memory image for C2 indicators and lateral movement"

    def list_connections(self, memory_image: str) -> dict[str, Any]:
        result = self.run_plugin(memory_image, "windows.netscan.NetScan")
        if not result["success"]:
            result = self.run_plugin(memory_image, "windows.netstat.NetStat")
        return result

    def find_suspicious(self, connections: list[dict]) -> list[dict]:
        flags = []
        for conn in connections:
            foreign_addr = conn.get("ForeignAddr") or conn.get("RemoteAddr") or ""
            foreign_port_raw = conn.get("ForeignPort") or conn.get("RemotePort") or 0
            owner = (conn.get("Owner") or conn.get("Process") or "").lower()
            state = (conn.get("State") or "").upper()
            issues = []

            try:
                foreign_port = int(foreign_port_raw)
            except (ValueError, TypeError):
                foreign_port = 0

            if foreign_addr and _is_external(foreign_addr) and foreign_addr not in ("*", "0.0.0.0", "::"):
                if foreign_port in C2_PORTS:
                    issues.append(f"C2_PORT: {foreign_addr}:{foreign_port}")
                if state == "ESTABLISHED":
                    issues.append(f"EXTERNAL_ESTABLISHED: {foreign_addr}:{foreign_port}")

            if owner in SUSPICIOUS_PROCS and state == "ESTABLISHED":
                issues.append(f"SUSPICIOUS_PROCESS_NETWORK: {owner}")

            if issues:
                flags.append({
                    "owner": owner,
                    "remote": f"{foreign_addr}:{foreign_port}",
                    "state": state,
                    "issues": issues,
                    "connection": conn,
                })
        return flags
