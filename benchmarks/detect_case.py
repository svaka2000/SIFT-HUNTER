"""
Deterministic case detector — NO LLM, NO SIFT binaries, NO API key.

Loads a benchmark case's pre-exported forensic artifacts (Eric Zimmerman / Volatility
CSV exports) and runs SIFT-HUNTER's detection logic (the find_suspicious /
find_persistence methods on each tool) plus offline MITRE ATT&CK mapping. This proves
the forensic engine works end-to-end on a realistic multi-artifact incident without a
SIFT Workstation or a model key — the agent pipeline (benchmarks/runner.py) layers LLM
reasoning on top of exactly these detectors.

    python -m benchmarks.detect_case benchmarks/cases/case001
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from sift_hunter.mcp_server.tools.disk.mft import MFTTool
from sift_hunter.mcp_server.tools.disk.prefetch import PrefetchTool
from sift_hunter.mcp_server.tools.disk.registry import RegistryTool
from sift_hunter.mcp_server.tools.enrichment.mitre_attack import map_to_ttps
from sift_hunter.mcp_server.tools.memory.network import NetworkTool
from sift_hunter.mcp_server.tools.memory.processes import ProcessTool
from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv_file


def detect(case_dir: str) -> dict:
    """Run every deterministic detector over a case directory's artifacts."""
    case_path = Path(case_dir)
    ev = case_path / "evidence"

    detections: list[dict] = []
    corpus: list[str] = []

    def record(artifact: str, items: list[dict], summarize) -> None:
        for it in items:
            summary = summarize(it)
            detections.append({"artifact": artifact, "summary": summary, "raw": it})
            corpus.extend(summary)

    # Disk: MFT — timestomping + suspicious location
    mft = MFTTool()
    mft_entries = mft.parse_csv(str(ev / "mft.csv"))
    record("mft", mft.find_suspicious(mft_entries), lambda d: d.get("_flags", []))
    corpus += [f"{e.get('FileName', '')} {e.get('ParentPath', '')}" for e in mft_entries]

    # Disk: Prefetch — execution history (also surfaces MSHTA LOLBin for MITRE)
    pf_entries = parse_ez_csv_file(str(ev / "prefetch.csv"))
    record("prefetch", PrefetchTool().find_suspicious(pf_entries), lambda d: d.get("issues", []))
    corpus += [e.get("ExecutableName", "") for e in pf_entries]

    # Disk: Registry — persistence
    reg_entries = parse_ez_csv_file(str(ev / "registry.csv"))
    record(
        "registry",
        RegistryTool().find_persistence(reg_entries),
        lambda d: [f"{d.get('type')}: {d.get('key')} -> {d.get('value')}={d.get('data')}"],
    )
    corpus += [e.get("KeyPath", "") for e in reg_entries]

    # Memory: Processes — masquerade / unexpected parent
    ps_entries = parse_ez_csv_file(str(ev / "pslist.csv"))
    record("pslist", ProcessTool().find_suspicious(ps_entries), lambda d: d.get("issues", []))

    # Memory: Network — C2
    net_entries = parse_ez_csv_file(str(ev / "netscan.csv"))
    record("netscan", NetworkTool().find_suspicious(net_entries), lambda d: d.get("issues", []))
    corpus += [f"{e.get('ForeignAddr', '')}:{e.get('ForeignPort', '')}" for e in net_entries]

    ttps = map_to_ttps("\n".join(p for p in corpus if p))

    artifacts = ("mft", "prefetch", "registry", "pslist", "netscan")
    return {
        "case_id": _meta(case_path).get("case_id", case_path.name),
        "artifacts": {a: sum(1 for d in detections if d["artifact"] == a) for a in artifacts},
        "detections": detections,
        "mitre_ttps": [t._asdict() for t in ttps],
    }


def _meta(case_path: Path) -> dict:
    f = case_path / "case.json"
    return json.loads(f.read_text()) if f.exists() else {}


def main() -> None:
    case_dir = sys.argv[1] if len(sys.argv) > 1 else "benchmarks/cases/case001"
    r = detect(case_dir)
    print(f"SIFT-HUNTER deterministic detection — {r['case_id']} (no LLM, no SIFT binaries)")
    print("=" * 72)
    for d in r["detections"]:
        for s in d["summary"]:
            print(f"  [{d['artifact']:8}] {s}")
    print("-" * 72)
    print("MITRE ATT&CK techniques inferred (offline):")
    for t in r["mitre_ttps"]:
        print(f"  {t['technique_id']:11} {t['technique_name']} ({t['tactic']})  conf={t['confidence']}")
    print("=" * 72)
    flagged = sum(1 for v in r["artifacts"].values() if v)
    print(f"{len(r['detections'])} suspicious artifacts across {flagged}/5 evidence sources.")


if __name__ == "__main__":
    main()
