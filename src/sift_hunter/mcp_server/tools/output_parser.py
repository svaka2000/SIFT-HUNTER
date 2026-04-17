"""Parsers for forensic tool output formats: CSV, JSON, Volatility text tables."""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any


def parse_ez_csv(content: str) -> list[dict[str, str]]:
    """Parse Eric Zimmerman tool CSV output.

    Handles BOM, whitespace-padded headers, empty files.
    """
    if not content or not content.strip():
        return []

    # Strip BOM if present
    if content.startswith("\ufeff"):
        content = content[1:]

    reader = csv.DictReader(io.StringIO(content))
    rows = []
    for row in reader:
        # Strip whitespace from all keys and values
        clean = {k.strip(): v.strip() if v else "" for k, v in row.items() if k}
        if any(clean.values()):
            rows.append(clean)
    return rows


def parse_ez_csv_file(path: str) -> list[dict[str, str]]:
    """Parse an EZ tool CSV file from disk."""
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            return parse_ez_csv(f.read())
    except FileNotFoundError:
        return []


def parse_volatility_text(output: str) -> list[dict[str, Any]]:
    """Parse Volatility3 fixed-width text table output.

    Detects the header/separator line and parses column data.
    """
    if not output or not output.strip():
        return []

    lines = output.splitlines()
    # Find the header line (before the separator of dashes/asterisks)
    header_idx = -1
    sep_idx = -1
    for i, line in enumerate(lines):
        if re.match(r'^[\-\*]+', line.strip()):
            sep_idx = i
            header_idx = i - 1
            break

    if header_idx < 0:
        # No separator found — try to use the first non-empty line as header
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith("Volatility") and not line.startswith("Progress"):
                header_idx = i
                sep_idx = i + 1
                break

    if header_idx < 0:
        return []

    header_line = lines[header_idx]
    headers = [h.strip() for h in re.split(r'\s{2,}', header_line.strip()) if h.strip()]

    rows = []
    for line in lines[sep_idx + 1:]:
        if not line.strip():
            continue
        if line.startswith("*") or line.startswith("-"):
            continue
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) >= len(headers):
            row = dict(zip(headers, parts))
            rows.append(row)
        elif parts:
            # Partial row — include what we have
            row = dict(zip(headers[:len(parts)], parts))
            rows.append(row)

    return rows


def parse_volatility_json(output: str) -> list[dict[str, Any]]:
    """Parse Volatility3 JSON output (preferred when -r json is used)."""
    if not output or not output.strip():
        return []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Some plugins wrap in {"rows": [...]}
            for key in ("rows", "data", "entries", "results"):
                if key in data and isinstance(data[key], list):
                    return data[key]
        return [data] if data else []
    except json.JSONDecodeError:
        return []


def parse_regripper(output: str) -> dict[str, Any]:
    """Parse RegRipper text output into structured dict."""
    if not output:
        return {"raw": output}
    result: dict[str, Any] = {"entries": [], "raw": output[:2000]}
    current: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current:
                result["entries"].append(current)
                current = {}
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            current[key.strip()] = value.strip()
        else:
            current.setdefault("data", "")
            current["data"] += line + "\n"
    if current:
        result["entries"].append(current)
    return result


def parse_sleuthkit_fls(output: str) -> list[dict[str, str]]:
    """Parse Sleuth Kit fls mactime output."""
    rows = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) >= 9:
            rows.append({
                "md5": parts[0],
                "name": parts[1],
                "inode": parts[2],
                "mode_as_string": parts[3],
                "uid": parts[4],
                "gid": parts[5],
                "size": parts[6],
                "atime": parts[7],
                "mtime": parts[8],
                "ctime": parts[9] if len(parts) > 9 else "",
                "crtime": parts[10] if len(parts) > 10 else "",
            })
    return rows
