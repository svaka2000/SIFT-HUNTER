"""
Network connection analysis via Volatility3 netscan/netstat.
Identifies C2 connections, lateral movement, and exfiltration channels.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from core.models import ToolExecution
from mcp_server.tools.memory.volatility import Volatility3Tool


class NetworkConnection(BaseModel):
    pid: int = 0
    process_name: str = ""
    local_addr: str = ""
    local_port: int = 0
    foreign_addr: str = ""
    foreign_port: int = 0
    state: str = ""
    protocol: str = ""
    create_time: Optional[datetime] = None
    raw: dict[str, Any] = {}


class SuspiciousConnection(BaseModel):
    connection: NetworkConnection
    reason: str
    severity: str
    ioc_type: str = ""  # C2, EXFIL, LATERAL_MOVEMENT, PORT_SCAN


# Ports commonly used by C2 frameworks and exfiltration
SUSPICIOUS_PORTS_OUTBOUND = {
    4444: "Metasploit default",
    4445: "Metasploit multi",
    8888: "Common C2 port",
    1337: "Leet/hacker convention port",
    31337: "Back Orifice",
    6666: "IRC botnet",
    6667: "IRC botnet",
    9999: "Common backdoor",
    12345: "NetBus",
    27374: "Sub7",
}

# Legitimate ports that should NOT have processes like powershell/cmd connecting
UNEXPECTED_PROCESS_PORTS = {
    80: ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
    443: ["powershell.exe", "cmd.exe", "wscript.exe"],
    8080: ["powershell.exe", "cmd.exe"],
}

# Private IP ranges (lateral movement indicators)
PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^192\.168\."),
]


class NetworkAnalysisTool(Volatility3Tool):
    tool_name = "vol3-network"

    def list_connections(
        self,
        memory_image: str,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, list[NetworkConnection]]:
        te, result = self.run_plugin(
            memory_image,
            "windows.netscan.NetScan",
            agent=agent,
            phase=phase,
            iteration=iteration,
        )
        connections = _rows_to_connections(result.rows)

        # Also try netstat for additional connections
        if not connections:
            te2, result2 = self.run_plugin(
                memory_image,
                "windows.netstat.NetStat",
                agent=agent,
                phase=phase,
                iteration=iteration,
            )
            connections = _rows_to_connections(result2.rows)
            # Use the richer execution record
            if connections:
                te = te2

        return te, connections

    def find_suspicious_connections(
        self,
        connections: list[NetworkConnection],
    ) -> list[SuspiciousConnection]:
        suspicious: list[SuspiciousConnection] = []

        for conn in connections:
            reasons: list[tuple[str, str, str]] = []

            # Known bad ports
            if conn.foreign_port in SUSPICIOUS_PORTS_OUTBOUND:
                reasons.append((
                    f"Connection to known C2 port {conn.foreign_port}: "
                    f"{SUSPICIOUS_PORTS_OUTBOUND[conn.foreign_port]}",
                    "HIGH",
                    "C2",
                ))

            # Unexpected process connecting outbound
            proc_lower = conn.process_name.lower()
            for port, bad_procs in UNEXPECTED_PROCESS_PORTS.items():
                if conn.foreign_port == port and proc_lower in bad_procs:
                    reasons.append((
                        f"Unexpected process {conn.process_name} connecting to port {port} (T1071)",
                        "HIGH",
                        "C2",
                    ))

            # Internal-to-internal connections from unusual processes (lateral movement)
            if _is_private(conn.foreign_addr) and conn.foreign_addr != conn.local_addr:
                if proc_lower in ["cmd.exe", "powershell.exe", "wscript.exe", "psexec.exe"]:
                    reasons.append((
                        f"Lateral movement indicator: {conn.process_name} -> {conn.foreign_addr} (T1021)",
                        "HIGH",
                        "LATERAL_MOVEMENT",
                    ))

            # High destination port suggesting non-standard channel
            if 49152 <= conn.foreign_port <= 65535 and conn.state == "ESTABLISHED":
                if proc_lower not in ["svchost.exe", "lsass.exe", "system"]:
                    reasons.append((
                        f"High ephemeral port connection from {conn.process_name} (possible C2 beacon)",
                        "MEDIUM",
                        "C2",
                    ))

            for reason, severity, ioc_type in reasons:
                suspicious.append(SuspiciousConnection(
                    connection=conn,
                    reason=reason,
                    severity=severity,
                    ioc_type=ioc_type,
                ))

        return sorted(suspicious, key=lambda s: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[s.severity])


def _rows_to_connections(rows: list[dict[str, Any]]) -> list[NetworkConnection]:
    connections: list[NetworkConnection] = []
    for row in rows:
        local = str(row.get("LocalAddr", row.get("LocalAddress", "")))
        foreign = str(row.get("ForeignAddr", row.get("RemoteAddress", "")))

        local_addr, local_port = _split_addr_port(local)
        foreign_addr, foreign_port = _split_addr_port(foreign)

        connections.append(NetworkConnection(
            pid=int(row.get("PID", row.get("Pid", row.get("Owner", {}).get("PID", 0)) if isinstance(row.get("Owner"), dict) else 0) or 0),
            process_name=str(row.get("Owner", row.get("Process", ""))),
            local_addr=local_addr,
            local_port=local_port,
            foreign_addr=foreign_addr,
            foreign_port=foreign_port,
            state=str(row.get("State", "")),
            protocol=str(row.get("Proto", row.get("Protocol", "TCP"))),
            create_time=_dt_or_none(str(row.get("Created", ""))),
            raw=row,
        ))
    return connections


def _split_addr_port(addr_port: str) -> tuple[str, int]:
    if ":" in addr_port:
        parts = addr_port.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except (ValueError, IndexError):
            return addr_port, 0
    return addr_port, 0


def _is_private(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_RANGES)


def _dt_or_none(val: str) -> Optional[datetime]:
    if not val or val in ("N/A", "-", ""):
        return None
    try:
        return datetime.fromisoformat(val.replace(" ", "T").rstrip("Z"))
    except (ValueError, AttributeError):
        return None
