"""
Volatility3 core wrapper — base for all memory analysis plugins.
Every memory tool goes through here to ensure consistent audit logging and path validation.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from core.models import ToolExecution
from mcp_server.config import config
from mcp_server.tools.base import BaseTool, run_tool_safe


class PluginResult(BaseModel):
    plugin: str
    memory_image: str
    rows: list[dict[str, Any]] = []
    columns: list[str] = []
    raw_output: str = ""
    error: Optional[str] = None
    execution_id: Optional[str] = None


class Volatility3Tool(BaseTool):
    tool_name = "vol3"

    def _build_command(self, evidence_path: str, args: dict[str, Any]) -> list[str]:
        plugin = args.get("plugin", "windows.pslist.PsList")
        extra = args.get("extra_args", [])
        cmd = [
            "vol3" if os.name != "nt" else "vol.exe",
            "-f", evidence_path,
            "-r", "json",  # Structured output — required for parsing
            plugin,
        ]
        cmd.extend(extra)
        return cmd

    def run_plugin(
        self,
        memory_image: str,
        plugin_name: str,
        extra_args: Optional[list[str]] = None,
        agent: str = "system",
        phase: str = "memory",
        iteration: int = 0,
    ) -> tuple[ToolExecution, PluginResult]:
        te = self.run(
            memory_image,
            agent=agent,
            phase=phase,
            iteration=iteration,
            extra_args={"plugin": plugin_name, "extra_args": extra_args or []},
        )

        result = PluginResult(plugin=plugin_name, memory_image=memory_image, raw_output=te.raw_output)
        result.execution_id = te.id

        if te.exit_code != 0 and not te.raw_output:
            result.error = te.error_message
            return te, result

        # Try JSON parse first (vol3 -r json)
        parsed = _parse_vol3_json(te.raw_output)
        if parsed:
            result.rows = parsed.get("rows", [])
            result.columns = parsed.get("columns", [])
        else:
            # Fallback: parse text table output
            result.rows = _parse_vol3_text(te.raw_output, plugin_name)

        return te, result

    def list_available_plugins(
        self,
        memory_image: str,
        agent: str = "system",
    ) -> list[str]:
        """List all available Volatility3 plugins for this memory image."""
        te = run_tool_safe(
            ["vol3", "--info"],
            evidence_path=memory_image,
            tool_name="vol3-info",
            agent=agent,
            allowed_roots=self._allowed_roots,
        )
        plugins: list[str] = []
        for line in te.raw_output.splitlines():
            line = line.strip()
            if "." in line and not line.startswith("#") and not line.startswith("-"):
                plugin_name = line.split()[0] if line.split() else ""
                if plugin_name:
                    plugins.append(plugin_name)
        return plugins


def _parse_vol3_json(raw: str) -> Optional[dict]:
    """Parse Volatility3 JSON output format."""
    # vol3 JSON output starts with a line containing the column headers then rows
    for start in range(len(raw)):
        if raw[start] == "{":
            try:
                return json.loads(raw[start:])
            except json.JSONDecodeError:
                pass
    # Try to find JSON array
    for i, char in enumerate(raw):
        if char == "[":
            try:
                rows = json.loads(raw[i:])
                if isinstance(rows, list):
                    return {"rows": rows, "columns": list(rows[0].keys()) if rows else []}
            except (json.JSONDecodeError, AttributeError):
                pass
    return None


def _parse_vol3_text(raw: str, plugin: str) -> list[dict[str, Any]]:
    """Fallback text table parser for vol3 output."""
    rows: list[dict[str, Any]] = []
    lines = [l for l in raw.splitlines() if l.strip() and not l.startswith("*")]

    if len(lines) < 2:
        return rows

    # First non-empty, non-warning line is the header
    header_line = ""
    data_lines: list[str] = []
    for line in lines:
        if line.startswith("Volatility 3") or line.startswith("Progress:") or line.startswith("WARNING"):
            continue
        if not header_line:
            header_line = line
        else:
            data_lines.append(line)

    if not header_line:
        return rows

    headers = header_line.split()
    for line in data_lines:
        parts = line.split(None, len(headers) - 1)
        if parts:
            row = {}
            for i, h in enumerate(headers):
                row[h] = parts[i] if i < len(parts) else ""
            rows.append(row)

    return rows
