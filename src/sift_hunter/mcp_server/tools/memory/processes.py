"""Process analysis — wraps Volatility3 pslist, pstree, cmdline, dlllist."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any

from sift_hunter.mcp_server.tools.memory.volatility import VolatilityTool


SYSTEM_PROCESS_PARENTS = {
    "smss.exe": ["System"],
    "csrss.exe": ["smss.exe"],
    "wininit.exe": ["smss.exe"],
    "winlogon.exe": ["smss.exe"],
    # wininit.exe = Windows Vista+ lineage; winlogon.exe = Windows XP lineage (services.exe
    # and lsass.exe are spawned by winlogon on XP, which has no wininit.exe).
    "lsass.exe": ["wininit.exe", "winlogon.exe"],
    "services.exe": ["wininit.exe", "winlogon.exe"],
    "svchost.exe": ["services.exe"],
    "explorer.exe": ["userinit.exe", "winlogon.exe"],
    "taskhost.exe": ["services.exe"],
    "spoolsv.exe": ["services.exe"],
}

SYSTEM32_PROCS = {"lsass.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
                  "spoolsv.exe", "smss.exe", "svchost.exe"}


class ProcessTool(VolatilityTool):
    tool_name = "process_analyzer"
    description = "Analyze processes in memory image for suspicious activity"

    def list_processes(self, memory_image: str) -> dict[str, Any]:
        return self.run_plugin(memory_image, "windows.pslist.PsList")

    def get_process_tree(self, memory_image: str) -> dict[str, Any]:
        return self.run_plugin(memory_image, "windows.pstree.PsTree")

    def get_cmdlines(self, memory_image: str) -> dict[str, Any]:
        return self.run_plugin(memory_image, "windows.cmdline.CmdLine")

    def get_dlls(self, memory_image: str, pid: int | None = None) -> dict[str, Any]:
        args = ["--pid", str(pid)] if pid else []
        return self.run_plugin(memory_image, "windows.dlllist.DllList", args)

    def find_suspicious(self, processes: list[dict]) -> list[dict]:
        flags = []
        for proc in processes:
            name = (proc.get("ImageFileName") or proc.get("Name") or "").lower()
            path = (proc.get("Path") or "").lower()
            ppid_name = (proc.get("Parent") or proc.get("ParentName") or "").lower()
            issues = []

            expected_parents = SYSTEM_PROCESS_PARENTS.get(name)
            if expected_parents and ppid_name and ppid_name not in [p.lower() for p in expected_parents]:
                issues.append(f"UNEXPECTED_PARENT: {ppid_name} (expected {expected_parents})")

            if name in SYSTEM32_PROCS and path and "system32" not in path:
                issues.append(f"WRONG_PATH: {path}")

            if re.search(r"svchost|csrss|lsass|smss", name) and name not in SYSTEM32_PROCS:
                issues.append(f"SYSTEM_PROCESS_MASQUERADE: {name}")

            if name.endswith(".exe"):
                base = name[:-4]
                if len(set(base)) / max(len(base), 1) < 0.4:
                    issues.append(f"POSSIBLE_RANDOM_NAME: {name}")

            if issues:
                flags.append({"name": name, "issues": issues, "process": proc})
        return flags
