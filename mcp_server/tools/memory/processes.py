"""
Process analysis via Volatility3 — pslist, pstree, cmdline, dlllist.
Identifies suspicious processes: unusual parents, injected code, LOLBins abuse.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from core.models import ToolExecution
from mcp_server.tools.memory.volatility import PluginResult, Volatility3Tool


class Process(BaseModel):
    pid: int = 0
    ppid: int = 0
    name: str = ""
    create_time: Optional[datetime] = None
    exit_time: Optional[datetime] = None
    threads: int = 0
    handles: int = 0
    session_id: int = 0
    wow64: bool = False
    cmdline: str = ""
    path: str = ""
    dlls: list[str] = []
    raw: dict[str, Any] = {}


class ProcessTree(BaseModel):
    root_processes: list[dict] = []
    all_processes: list[Process] = []
    orphan_processes: list[Process] = []


class SuspiciousProcess(BaseModel):
    process: Process
    reason: str
    severity: str  # HIGH, MEDIUM, LOW
    mitre_technique: str = ""


class ProcessCmdline(BaseModel):
    pid: int
    name: str
    cmdline: str
    suspicious: bool = False
    reason: str = ""


class DLLEntry(BaseModel):
    pid: int
    name: str = ""
    base: str = ""
    size: str = ""
    path: str = ""
    load_reason: str = ""


# Known-malicious parent-child relationships
SUSPICIOUS_PARENTS = {
    "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "lsass.exe": ["cmd.exe", "powershell.exe"],
    "svchost.exe": ["cmd.exe", "powershell.exe"],
}

# LOLBins commonly abused for execution
LOLBINS = frozenset([
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "msiexec.exe", "cmstp.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe",
])


class ProcessAnalysisTool(Volatility3Tool):
    tool_name = "vol3-processes"

    def list_processes(
        self,
        memory_image: str,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, list[Process]]:
        te, result = self.run_plugin(
            memory_image,
            "windows.pslist.PsList",
            agent=agent,
            phase=phase,
            iteration=iteration,
        )
        return te, _rows_to_processes(result.rows)

    def get_process_tree(
        self,
        memory_image: str,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, ProcessTree]:
        te, result = self.run_plugin(
            memory_image,
            "windows.pstree.PsTree",
            agent=agent,
            phase=phase,
            iteration=iteration,
        )
        processes = _rows_to_processes(result.rows)
        pid_map = {p.pid: p for p in processes}
        roots: list[dict] = []
        orphans: list[Process] = []

        for proc in processes:
            if proc.ppid not in pid_map and proc.ppid != 0:
                orphans.append(proc)

        return te, ProcessTree(all_processes=processes, orphan_processes=orphans)

    def find_suspicious_processes(
        self,
        processes: list[Process],
    ) -> list[SuspiciousProcess]:
        suspicious: list[SuspiciousProcess] = []
        pid_map = {p.pid: p for p in processes}

        for proc in processes:
            reasons: list[tuple[str, str, str]] = []

            # Check for suspicious parent-child
            parent = pid_map.get(proc.ppid)
            if parent:
                parent_name = parent.name.lower()
                child_name = proc.name.lower()
                for known_parent, bad_children in SUSPICIOUS_PARENTS.items():
                    if known_parent in parent_name and child_name in bad_children:
                        reasons.append((
                            f"Suspicious spawn: {parent.name} -> {proc.name} (T1059)",
                            "HIGH",
                            "T1059",
                        ))

            # LOLBin execution
            if proc.name.lower() in LOLBINS:
                reasons.append((
                    f"LOLBin execution: {proc.name} (T1218)",
                    "MEDIUM",
                    "T1218",
                ))

            # Suspicious command line indicators
            cmdline_lower = proc.cmdline.lower()
            if any(ioc in cmdline_lower for ioc in [
                "invoke-expression", "iex(", "downloadstring",
                "frombase64string", "encoded", "bypass",
                "-enc ", "-nop ", "-w hidden",
                "webclient", "net.webclient",
            ]):
                reasons.append((
                    f"Obfuscated/encoded PowerShell indicators in cmdline (T1059.001)",
                    "HIGH",
                    "T1059.001",
                ))

            # Unusual path for system processes
            if proc.name.lower() in ["svchost.exe", "lsass.exe", "services.exe", "csrss.exe"]:
                if proc.path and "\\system32\\" not in proc.path.lower():
                    reasons.append((
                        f"System process {proc.name} running from non-standard path (T1036.005)",
                        "HIGH",
                        "T1036.005",
                    ))

            for reason, severity, technique in reasons:
                suspicious.append(SuspiciousProcess(
                    process=proc,
                    reason=reason,
                    severity=severity,
                    mitre_technique=technique,
                ))

        return sorted(suspicious, key=lambda s: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[s.severity])

    def get_process_cmdlines(
        self,
        memory_image: str,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, list[ProcessCmdline]]:
        te, result = self.run_plugin(
            memory_image,
            "windows.cmdline.CmdLine",
            agent=agent,
            phase=phase,
            iteration=iteration,
        )
        cmdlines: list[ProcessCmdline] = []
        for row in result.rows:
            cmdline = str(row.get("Args", row.get("Cmdline", row.get("CommandLine", ""))))
            suspicious = False
            reason = ""
            if any(ioc in cmdline.lower() for ioc in [
                "invoke-expression", "iex(", "downloadstring", "frombase64string",
                "bypass", "-enc ", "-nop ", "webclient",
            ]):
                suspicious = True
                reason = "Obfuscated/encoded content detected"

            cmdlines.append(ProcessCmdline(
                pid=int(row.get("PID", row.get("Pid", 0)) or 0),
                name=str(row.get("Name", row.get("ImageFileName", ""))),
                cmdline=cmdline,
                suspicious=suspicious,
                reason=reason,
            ))
        return te, cmdlines

    def get_process_dlls(
        self,
        memory_image: str,
        pid: int,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, list[DLLEntry]]:
        te, result = self.run_plugin(
            memory_image,
            "windows.dlllist.DllList",
            extra_args=["--pid", str(pid)],
            agent=agent,
            phase=phase,
            iteration=iteration,
        )
        dlls: list[DLLEntry] = []
        for row in result.rows:
            dlls.append(DLLEntry(
                pid=int(row.get("PID", row.get("Pid", pid)) or pid),
                name=str(row.get("Name", "")),
                base=str(row.get("Base", "")),
                size=str(row.get("Size", "")),
                path=str(row.get("Path", row.get("FullDllName", ""))),
                load_reason=str(row.get("LoadReason", "")),
            ))
        return te, dlls


def _rows_to_processes(rows: list[dict[str, Any]]) -> list[Process]:
    processes: list[Process] = []
    for row in rows:
        processes.append(Process(
            pid=int(row.get("PID", row.get("Pid", 0)) or 0),
            ppid=int(row.get("PPID", row.get("PPid", row.get("ParentPID", 0))) or 0),
            name=str(row.get("ImageFileName", row.get("Name", ""))),
            threads=int(row.get("Threads", row.get("ActiveThreads", 0)) or 0),
            handles=int(row.get("Handles", 0) or 0),
            session_id=int(row.get("SessionId", row.get("Sess", 0)) or 0),
            wow64=str(row.get("Wow64", "False")).lower() in ("true", "1"),
            create_time=_dt_or_none(str(row.get("CreateTime", ""))),
            exit_time=_dt_or_none(str(row.get("ExitTime", ""))),
            raw=row,
        ))
    return processes


def _dt_or_none(val: str) -> Optional[datetime]:
    if not val or val in ("N/A", "-", ""):
        return None
    try:
        return datetime.fromisoformat(val.replace(" ", "T").rstrip("Z"))
    except (ValueError, AttributeError):
        return None
