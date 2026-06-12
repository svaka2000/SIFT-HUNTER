# Adding New Forensic Tools to SIFT-HUNTER

This guide walks through adding a new forensic tool wrapper in under 1 hour.
We'll use a hypothetical `lnkparse` (Windows LNK file parser) as the example.

---

## Overview

Every forensic tool in SIFT-HUNTER follows this pattern:

```
CLI binary → Tool wrapper (Python) → Pydantic model → MCP server tool → Agent
```

You need to touch exactly 4 files:
1. `mcp_server/tools/disk/lnkparse.py` - the tool wrapper
2. `core/models.py` - add result model (optional but recommended)
3. `mcp_server/server.py` - register the MCP tool
4. `tests/test_tools.py` - add unit tests

---

## Step 1: Understand Your Binary (5 min)

Run the tool manually and observe its output:

```bash
# Example: What does lnkparse output?
lnkparse /cases/evidence/Recent/suspicious.lnk

# Expected output:
# Target: C:\Users\victim\AppData\Local\Temp\evil.exe
# Machine: WORKSTATION-01
# Created: 2024-01-15 14:23:01
# Modified: 2024-01-15 14:23:01
```

Note:
- The binary name (first argument to subprocess)
- Its argument pattern (positional vs flags)
- Its output format (CSV, JSON, or text)
- What failure looks like (exit code, stderr)

---

## Step 2: Create the Tool Wrapper (25 min)

Create `mcp_server/tools/disk/lnkparse.py`:

```python
"""LNK file parser wrapper - extracts shortcut metadata including target paths."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from mcp_server.tools.base import run_tool_safe
from core.models import ToolExecution


@dataclass
class LNKEntry:
    """Parsed LNK (Windows shortcut) file entry."""
    lnk_path: str
    target_path: str = ""
    working_directory: str = ""
    machine_id: str = ""
    created: str = ""
    modified: str = ""
    accessed: str = ""
    network_path: str = ""
    is_suspicious: bool = False
    suspicion_reason: str = ""


@dataclass
class LNKResult:
    """Result from parsing LNK files."""
    tool_execution: ToolExecution
    entries: list[LNKEntry] = field(default_factory=list)
    error: str = ""


def parse_lnk_files(
    evidence_path: str,
    agent: str = "disk_analyst",
    phase: str = "disk",
    iteration: int = 1,
) -> LNKResult:
    """
    Parse Windows LNK (shortcut) files.

    Args:
        evidence_path: Path to LNK file or directory containing LNK files
        agent: Agent requesting the analysis (for audit logging)
        phase: Analysis phase (for audit logging)
        iteration: Iteration number (for audit logging)

    Returns:
        LNKResult with parsed entries or error
    """
    path = Path(evidence_path)

    # Build argument list - always shell=False, args as list
    if path.is_dir():
        args = [str(path), "--recursive", "--format", "csv"]
    else:
        args = [str(path), "--format", "csv"]

    exec_result = run_tool_safe(
        command="lnkparse",
        args=args,
        evidence_path=evidence_path,
        agent=agent,
        phase=phase,
        iteration=iteration,
        description="Parse Windows LNK shortcut files",
    )

    entries = _parse_lnkparse_output(exec_result.raw_output)
    return LNKResult(tool_execution=exec_result, entries=entries)


def find_suspicious_lnk(lnk_result: LNKResult) -> list[LNKEntry]:
    """
    Flag suspicious LNK files.

    Suspicious indicators:
    - Target in %TEMP%, %APPDATA%\Roaming, or unusual system paths
    - Target is a script (.bat, .ps1, .vbs, .js)
    - Target is a LOLBin (mshta.exe, wscript.exe, etc.)
    - Network target path (\\\\server\\share)
    - Machine ID mismatch (LNK from a different machine)
    """
    suspicious: list[LNKEntry] = []
    lolbins = {"mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe"}
    script_exts = {".bat", ".ps1", ".vbs", ".js", ".hta", ".cmd"}
    suspicious_dirs = {r"\temp\\", r"\tmp\\", r"\appdata\roaming\\", r"\appdata\local\temp\\"}

    for entry in lnk_result.entries:
        target_lower = entry.target_path.lower()
        reasons = []

        # Check for LOLBins
        for lolbin in lolbins:
            if lolbin in target_lower:
                reasons.append(f"LOLBin target: {lolbin}")
                break

        # Check for script extensions
        for ext in script_exts:
            if target_lower.endswith(ext):
                reasons.append(f"Script target: {Path(entry.target_path).name}")
                break

        # Check for suspicious directories
        for sus_dir in suspicious_dirs:
            if sus_dir in target_lower:
                reasons.append(f"Suspicious directory: {sus_dir.strip(chr(92))}")
                break

        # Check for network paths
        if entry.target_path.startswith("\\\\") or entry.network_path:
            reasons.append("Network path target - possible lateral movement artifact")

        if reasons:
            entry.is_suspicious = True
            entry.suspicion_reason = "; ".join(reasons)
            suspicious.append(entry)

    return suspicious


def _parse_lnkparse_output(raw_output: str) -> list[LNKEntry]:
    """Parse lnkparse CSV output into LNKEntry objects."""
    entries: list[LNKEntry] = []
    lines = raw_output.strip().split("\n")

    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue

        # Simple regex for CSV parsing - adjust to match actual tool output format
        parts = line.split(",")
        if len(parts) < 3:
            continue

        entry = LNKEntry(
            lnk_path=parts[0].strip().strip('"'),
            target_path=parts[1].strip().strip('"') if len(parts) > 1 else "",
            machine_id=parts[2].strip().strip('"') if len(parts) > 2 else "",
            created=parts[3].strip().strip('"') if len(parts) > 3 else "",
        )
        entries.append(entry)

    return entries
```

### Key Rules to Follow

1. **`run_tool_safe()` not `subprocess.run()`** - The base function enforces security, audit logging, and path validation automatically.
2. **`args` as a list** - Never concatenate into a string. `["lnkparse", str(path)]` not `f"lnkparse {path}"`.
3. **Graceful failure** - If `exec_result.error` is set, return a result with the error field populated. Don't crash.
4. **Separate parsing from execution** - `parse_lnk_files()` calls the binary; `find_suspicious_lnk()` analyzes the results. Keep them separate for testability.
5. **Structured return types** - Return dataclasses, not dicts or raw strings.

---

## Step 3: Add Result Model to core/models.py (5 min)

If your tool produces a result type that should appear in `Finding.raw_evidence_excerpt`, you don't necessarily need a new Pydantic model - the dataclass approach works fine for internal use. But if you want the result to appear in the audit trail as a typed object, add it to `core/models.py`:

```python
class LNKFinding(BaseModel):
    lnk_path: str
    target_path: str
    suspicion_reason: str
    mitre_ttp: str = "T1204.002"  # Malicious File
```

This is optional - the Finding model's `raw_evidence_excerpt` field can hold a string representation.

---

## Step 4: Register in MCP Server (10 min)

Open `mcp_server/server.py` and add your tool in the "Disk Forensics Tools" section:

```python
# In mcp_server/server.py, after the existing disk tool registrations:

@mcp.tool()
def parse_lnk_files_tool(
    evidence_path: str,
    agent: str = "disk_analyst",
) -> dict:
    """
    Parse Windows LNK (shortcut) files to find lateral movement artifacts.
    
    Returns suspicious shortcuts targeting LOLBins, scripts, temp directories,
    or network paths. LNK files persist even after the target is deleted.

    Args:
        evidence_path: Path to LNK file or directory of LNK files
        agent: Requesting agent name for audit trail
    """
    from mcp_server.tools.disk.lnkparse import parse_lnk_files, find_suspicious_lnk

    result = parse_lnk_files(evidence_path, agent=agent)
    suspicious = find_suspicious_lnk(result)

    return {
        "total_lnk_files": len(result.entries),
        "suspicious_count": len(suspicious),
        "suspicious_entries": [
            {
                "lnk_path": e.lnk_path,
                "target_path": e.target_path,
                "suspicion_reason": e.suspicion_reason,
                "machine_id": e.machine_id,
            }
            for e in suspicious
        ],
        "tool_execution_id": result.tool_execution.id,
        "error": result.error,
    }
```

The `@mcp.tool()` decorator registers the function automatically. FastMCP infers the schema from type hints and docstring.

---

## Step 5: Write Tests (15 min)

Add to `tests/test_tools.py`:

```python
class TestLNKParse:
    """Tests for LNK file parser."""

    def test_lolbin_target_flagged(self):
        """LNK pointing to mshta.exe should be flagged."""
        from mcp_server.tools.disk.lnkparse import LNKEntry, LNKResult, find_suspicious_lnk
        from unittest.mock import MagicMock

        fake_exec = MagicMock()
        fake_exec.raw_output = ""
        result = LNKResult(tool_execution=fake_exec)
        result.entries = [
            LNKEntry(
                lnk_path="C:\\Users\\victim\\Recent\\document.lnk",
                target_path="C:\\Windows\\System32\\mshta.exe",
            )
        ]
        suspicious = find_suspicious_lnk(result)
        assert len(suspicious) == 1
        assert "LOLBin" in suspicious[0].suspicion_reason

    def test_network_path_flagged(self):
        """LNK pointing to UNC path should be flagged."""
        from mcp_server.tools.disk.lnkparse import LNKEntry, LNKResult, find_suspicious_lnk
        from unittest.mock import MagicMock

        fake_exec = MagicMock()
        result = LNKResult(tool_execution=fake_exec)
        result.entries = [
            LNKEntry(
                lnk_path="C:\\Users\\victim\\Desktop\\share.lnk",
                target_path="\\\\attacker.local\\share\\payload.exe",
            )
        ]
        suspicious = find_suspicious_lnk(result)
        assert len(suspicious) == 1
        assert "Network path" in suspicious[0].suspicion_reason

    def test_normal_lnk_not_flagged(self):
        """Normal LNK (Notepad shortcut) should not be flagged."""
        from mcp_server.tools.disk.lnkparse import LNKEntry, LNKResult, find_suspicious_lnk
        from unittest.mock import MagicMock

        fake_exec = MagicMock()
        result = LNKResult(tool_execution=fake_exec)
        result.entries = [
            LNKEntry(
                lnk_path="C:\\Users\\victim\\Desktop\\notepad.lnk",
                target_path="C:\\Windows\\System32\\notepad.exe",
            )
        ]
        suspicious = find_suspicious_lnk(result)
        assert len(suspicious) == 0
```

Run your tests:

```bash
pytest tests/test_tools.py::TestLNKParse -v
```

---

## Step 6: Make the Agent Use It (optional, 10 min)

If you want the Disk Analyst agent to automatically run your new tool, open `agents/nodes/disk_analyst.py` and add a call in the `_run_all_disk_tools()` section:

```python
# In disk_analyst.py, inside the tool execution block:

# LNK file analysis
lnk_dirs = [
    str(Path(ep).parent / "Recent"),
    str(Path(ep).parent / "Users"),  # recurse for all user profiles
]
for lnk_dir in lnk_dirs:
    if Path(lnk_dir).exists():
        lnk_exec = run_tool_safe(
            command="lnkparse",
            args=[lnk_dir, "--recursive", "--format", "csv"],
            evidence_path=lnk_dir,
            agent="disk_analyst",
            phase=state["current_phase"],
            iteration=state["iteration_count"],
            description="Parse LNK shortcut files",
        )
        tool_outputs.append(f"=== LNK FILES ===\n{lnk_exec.raw_output}")
        new_executions.append(lnk_exec)
```

The LLM agent will automatically incorporate the output into its analysis.

---

## Checklist

Before opening a PR:

- [ ] Binary name added to `BLOCKED_COMMANDS` exclusion list? (It should NOT be in the blocklist - only destructive commands are blocked. Forensic read-only tools are allowed by default.)
- [ ] Tool wrapper uses `run_tool_safe()` not raw `subprocess.run()`
- [ ] Arguments passed as list, not string
- [ ] Tool handles missing binary gracefully (logs error, doesn't crash)
- [ ] Tool handles missing/corrupted evidence gracefully
- [ ] Unit tests cover: suspicious finding detected, clean case not flagged, error case
- [ ] MCP server tool registered with clear docstring
- [ ] No writes to evidence directory (read-only only)

---

## Total Time Budget

| Step | Time |
|------|------|
| Understand binary output | 5 min |
| Write tool wrapper | 25 min |
| Add Pydantic model (optional) | 5 min |
| Register in MCP server | 10 min |
| Write tests | 15 min |
| **Total** | **~60 min** |

That's the target. If a new tool is taking longer than 90 minutes, something is wrong - the base infrastructure handles security, audit logging, and path validation for you.

---

## Common Mistakes

**Mistake:** Using `shell=True` or string concatenation in subprocess.
**Fix:** Always `run_tool_safe()` with a list of args.

**Mistake:** Returning raw strings from MCP tools.
**Fix:** Return a `dict` with typed fields. Agents can parse dicts; they struggle with free-form strings.

**Mistake:** Crashing when the binary is missing.
**Fix:** Catch `FileNotFoundError` and return a result with `error="Tool not found: lnkparse"`.

**Mistake:** Adding the tool binary to `BLOCKED_COMMANDS`.
**Fix:** The blocklist is for destructive/network tools. Forensic read-only tools are allowed automatically.

**Mistake:** Not adding to the MCP server, only to the agent.
**Fix:** The MCP server is the contract. Register the tool there so external agents (Protocol SIFT, etc.) can also call it.
