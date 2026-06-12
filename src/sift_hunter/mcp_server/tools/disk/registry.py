"""Registry analysis tool - wraps RECmd / RegRipper."""
from __future__ import annotations
from pathlib import Path
from typing import Any

from sift_hunter.mcp_server.tools.base import BaseTool
from sift_hunter.mcp_server.tools.output_parser import parse_regripper


PERSISTENCE_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SOFTWARE\Classes\exefile\shell\open\command",
]

AUTORUN_VALUE_KEYS = ["Run", "RunOnce", "RunOnceEx", "RunServices", "RunServicesOnce"]


class RegistryTool(BaseTool):
    tool_name = "registry_parser"
    binary_name = "RECmd"
    description = "Parse Windows registry hives for persistence, artifacts, and attacker TTPs"

    def analyze(self, hive_path: str, output_dir: str) -> dict[str, Any]:
        src = Path(hive_path)
        out = Path(output_dir)
        result = self._execute(
            args=["-f", str(src), "--csv", str(out), "--csvf", "registry.csv", "--all"],
            evidence_path=src,
            output_dir=out,
        )
        entries = []
        if result.success and (out / "registry.csv").exists():
            from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv_file
            entries = parse_ez_csv_file(str(out / "registry.csv"))
        return {"entries": entries, "raw": result.stdout[:2000], "tool": "RECmd", "source": str(src)}

    def run_regripper(self, hive_path: str, plugin: str = "all") -> dict[str, Any]:
        src = Path(hive_path)
        result = self._execute(
            args=["-r", str(src), "-f", plugin],
            evidence_path=src,
            output_dir=None,
        )
        parsed = parse_regripper(result.stdout) if result.success else []
        return {"entries": parsed, "raw": result.stdout[:3000], "tool": f"RegRipper:{plugin}"}

    def find_persistence(self, entries: list[dict]) -> list[dict]:
        findings = []
        for e in entries:
            key = e.get("KeyPath") or e.get("Key") or ""
            value = e.get("ValueName") or e.get("Value") or ""
            data = e.get("ValueData") or e.get("Data") or ""
            for pk in PERSISTENCE_KEYS:
                if pk.lower() in key.lower():
                    findings.append({
                        "type": "PERSISTENCE_KEY",
                        "key": key,
                        "value": value,
                        "data": data,
                        "matched_pattern": pk,
                        "entry": e,
                    })
                    break
        return findings

    def find_user_activity(self, entries: list[dict]) -> list[dict]:
        activity = []
        for e in entries:
            key = (e.get("KeyPath") or "").lower()
            if "recentdocs" in key or "userassist" in key or "shellbags" in key or "typedurls" in key:
                activity.append({"type": "USER_ACTIVITY", "key": key, "entry": e})
        return activity
