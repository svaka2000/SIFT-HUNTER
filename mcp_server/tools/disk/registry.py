"""
RegRipper / RECmd wrapper — parses Windows registry hives.
Focuses on persistence keys, user activity, and system configuration artifacts.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from core.models import ToolExecution
from mcp_server.config import config
from mcp_server.tools.base import BaseTool


class RegistryValue(BaseModel):
    key_path: str = ""
    value_name: str = ""
    value_data: str = ""
    value_type: str = ""
    last_write: Optional[datetime] = None


class PersistenceEntry(BaseModel):
    key_path: str
    value_name: str
    value_data: str
    persistence_type: str  # Run key, Service, Scheduled Task, etc.
    severity: str  # HIGH, MEDIUM, LOW
    mitre_technique: str = ""


class UserActivity(BaseModel):
    username: str = ""
    last_login: Optional[datetime] = None
    recent_files: list[str] = []
    recent_urls: list[str] = []
    typed_paths: list[str] = []
    mru_items: list[str] = []


class RegistryResult(BaseModel):
    hive_type: str = ""
    values: list[RegistryValue] = []
    persistence_entries: list[PersistenceEntry] = []
    error: Optional[str] = None


# Persistence keys to check — each maps to a MITRE technique
PERSISTENCE_KEYS = {
    r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run": ("Run Key", "T1547.001", "HIGH"),
    r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce": ("RunOnce Key", "T1547.001", "HIGH"),
    r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon": ("Winlogon", "T1547.004", "HIGH"),
    r"SYSTEM\\CurrentControlSet\\Services": ("Service", "T1543.003", "HIGH"),
    r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options": ("IFEO", "T1546.012", "HIGH"),
    r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders": ("Shell Folders", "T1547.001", "MEDIUM"),
    r"SOFTWARE\\Classes\\.*\\shell\\open\\command": ("File Association", "T1546.001", "MEDIUM"),
    r"SOFTWARE\\Microsoft\\Office\\.*\\Common\\ResiliencyRegistry": ("Office Resilience", "T1137", "MEDIUM"),
}


class RegistryTool(BaseTool):
    tool_name = "RegRipper"

    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        hive_type = args.get("hive_type", "software")
        plugin = args.get("plugin", "all")
        return [
            "rip.pl",
            "-r", evidence_path,
            "-f", hive_type,
        ]

    def parse_registry_hive(
        self,
        hive_path: str,
        hive_type: str = "software",
        agent: str = "system",
        phase: str = "disk",
        iteration: int = 0,
    ) -> tuple[ToolExecution, RegistryResult]:
        te = self.run(
            hive_path,
            agent=agent,
            phase=phase,
            iteration=iteration,
            extra_args={"hive_type": hive_type},
        )
        result = RegistryResult(hive_type=hive_type)
        if te.exit_code != 0 and not te.raw_output:
            result.error = te.error_message
            return te, result

        result.values = _parse_regripper_output(te.raw_output)
        result.persistence_entries = self.find_persistence_keys(result)
        return te, result

    def find_persistence_keys(self, result: RegistryResult) -> list[PersistenceEntry]:
        persistence: list[PersistenceEntry] = []
        for value in result.values:
            path_lower = value.key_path.lower()
            for pattern, (ptype, technique, severity) in PERSISTENCE_KEYS.items():
                if re.search(pattern.lower(), path_lower):
                    # Skip empty or obviously benign values
                    if value.value_data and len(value.value_data.strip()) > 0:
                        persistence.append(PersistenceEntry(
                            key_path=value.key_path,
                            value_name=value.value_name,
                            value_data=value.value_data,
                            persistence_type=ptype,
                            severity=severity,
                            mitre_technique=technique,
                        ))
                    break
        return sorted(persistence, key=lambda p: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[p.severity])

    def find_user_activity(self, result: RegistryResult) -> list[UserActivity]:
        """Extract user activity artifacts from NTUSER.DAT hive output."""
        activity = UserActivity()
        for value in result.values:
            path_lower = value.key_path.lower()
            if "recentdocs" in path_lower:
                activity.recent_files.append(value.value_data)
            elif "typedpaths" in path_lower or "typedurls" in path_lower:
                activity.typed_paths.append(value.value_data)
            elif "mrulist" in path_lower or "mrulistex" in path_lower:
                activity.mru_items.append(value.value_data)
        return [activity] if (activity.recent_files or activity.mru_items) else []


def _parse_regripper_output(raw: str) -> list[RegistryValue]:
    """Parse RegRipper text output into RegistryValue objects."""
    values: list[RegistryValue] = []
    current_key = ""

    for line in raw.splitlines():
        line = line.rstrip()
        # Key header lines start with a path pattern
        if line.startswith("Software\\") or line.startswith("HKLM\\") or \
           line.startswith("HKCU\\") or line.startswith("System\\") or \
           (line and line[0].isupper() and "\\" in line and not line.startswith(" ")):
            current_key = line.split(" ")[0].strip()
        elif " -> " in line or " = " in line:
            sep = " -> " if " -> " in line else " = "
            parts = line.split(sep, 1)
            if len(parts) == 2:
                values.append(RegistryValue(
                    key_path=current_key,
                    value_name=parts[0].strip(),
                    value_data=parts[1].strip(),
                ))

    return values
