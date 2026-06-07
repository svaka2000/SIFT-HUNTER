"""
SIFT-HUNTER evaluation harness — MEASURED accuracy on recognized DFIR samples.

Runs the DETERMINISTIC detection layer (no LLM, no API key, no SIFT binaries) over a
set of benchmark cases and scores its findings against published ground truth, reporting
precision / recall / F1 per IOC category and a SHA-256 chain-of-custody manifest.

This is the evidentiary backbone of the project: the rule layer does the forensically
defensible work; the LLM agent layer (benchmarks/runner.py) adds reasoning on top. The
two canonical Volatility samples (zeus.vmem, cridex.vmem) have publicly documented
ground truth (see each case's PROVENANCE.md), so the numbers here are verifiable.

    python -m benchmarks.evaluate                       # all cases
    python -m benchmarks.evaluate benchmarks/cases/zeus-vmem
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from sift_hunter.core.evidence_integrity import hash_file
from sift_hunter.mcp_server.tools.disk.mft import MFTTool
from sift_hunter.mcp_server.tools.disk.prefetch import PrefetchTool
from sift_hunter.mcp_server.tools.disk.registry import RegistryTool
from sift_hunter.mcp_server.tools.memory.malware import MalwareTool
from sift_hunter.mcp_server.tools.memory.network import NetworkTool
from sift_hunter.mcp_server.tools.memory.processes import ProcessTool
from sift_hunter.mcp_server.tools.output_parser import parse_ez_csv_file

CASES_DIR = Path(__file__).resolve().parent / "cases"
DEFAULT_CASES = ["case001", "zeus-vmem", "cridex-vmem"]


def _id(ioc: dict) -> str:
    return ioc.get("id") or ioc.get("title") or str(ioc.get("must_contain"))


def detect_evidence(ev: Path) -> list[dict]:
    """Run each deterministic detector whose artifact file is present. No LLM."""
    dets: list[dict] = []

    def add(category: str, subject: str, extra: str) -> None:
        dets.append({"category": category, "text": f"{subject} {extra}".lower().strip()})

    if (ev / "mft.csv").exists():
        t = MFTTool()
        for d in t.find_suspicious(t.parse_csv(str(ev / "mft.csv"))):
            add("disk", d.get("FileName", ""), " ".join(d.get("_flags", [])))
    if (ev / "prefetch.csv").exists():
        for d in PrefetchTool().find_suspicious(parse_ez_csv_file(str(ev / "prefetch.csv"))):
            add("execution", d.get("executable", ""), " ".join(d.get("issues", [])))
    if (ev / "registry.csv").exists():
        for d in RegistryTool().find_persistence(parse_ez_csv_file(str(ev / "registry.csv"))):
            add("persistence", f"{d.get('key','')} {d.get('value','')} {d.get('data','')}", d.get("type", ""))
    if (ev / "pslist.csv").exists():
        for d in ProcessTool().find_suspicious(parse_ez_csv_file(str(ev / "pslist.csv"))):
            add("process", d.get("name", ""), " ".join(d.get("issues", [])))
    if (ev / "netscan.csv").exists():
        for d in NetworkTool().find_suspicious(parse_ez_csv_file(str(ev / "netscan.csv"))):
            add("c2", d.get("remote", ""), " ".join(d.get("issues", [])) + " " + d.get("owner", ""))
    if (ev / "malfind.csv").exists():
        for d in MalwareTool().find_suspicious_injections(parse_ez_csv_file(str(ev / "malfind.csv"))):
            add("injection", f"{d.get('process','')} {d.get('pid','')}", " ".join(d.get("issues", [])))
    return dets


def _prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}


def score_case(case_dir: Path) -> dict:
    ev = case_dir / "evidence"
    gt = json.loads((case_dir / "ground_truth.json").read_text())
    meta = json.loads((case_dir / "case.json").read_text()) if (case_dir / "case.json").exists() else {}

    dets = detect_evidence(ev)
    alltext = " ".join(d["text"] for d in dets)
    gt_tokens = {tok.lower() for ioc in gt for tok in ioc["must_contain"]}

    # Precision: a detection is a true positive if it references a real ground-truth IOC.
    tp_dets = [d for d in dets if any(tok in d["text"] for tok in gt_tokens)]
    fp_dets = [d for d in dets if d not in tp_dets]

    # Recall: a ground-truth IOC is found if ALL its tokens appear in the detection output.
    found, missed = [], []
    for ioc in gt:
        (found if all(tok.lower() in alltext for tok in ioc["must_contain"]) else missed).append(ioc)

    # Deterministic-scoped recall excludes IOCs explicitly flagged as LLM-layer-only.
    gt_det = [i for i in gt if i.get("deterministic_expected", True)]
    found_det = [i for i in gt_det if i in found]

    manifest = {p.name: hash_file(str(p)) for p in sorted(ev.glob("*.csv"))}

    return {
        "case_id": meta.get("case_id", case_dir.name),
        "source": meta.get("source", ""),
        "n_detections": len(dets),
        "true_positives": len(tp_dets),
        "false_positives": len(fp_dets),
        "iocs_total": len(gt),
        "iocs_found": len(found),
        "iocs_missed": [_id(i) for i in missed],
        "metrics_all": _prf(len(found), len(fp_dets), len(gt) - len(found)),
        "recall_deterministic_scoped": round(len(found_det) / len(gt_det), 3) if gt_det else 1.0,
        "mitre_found": sorted({i["mitre_technique"] for i in found if i.get("mitre_technique")}),
        "mitre_total": sorted({i["mitre_technique"] for i in gt if i.get("mitre_technique")}),
        "chain_of_custody_sha256": manifest,
        "per_category": _per_category(gt, found, fp_dets),
    }


def _per_category(gt: list, found: list, fp_dets: list) -> dict:
    cats: dict[str, dict] = {}
    found_ids = {_id(i) for i in found}
    for ioc in gt:
        c = ioc.get("category", "other")
        cats.setdefault(c, {"total": 0, "found": 0})
        cats[c]["total"] += 1
        if _id(ioc) in found_ids:
            cats[c]["found"] += 1
    for c, v in cats.items():
        v["recall"] = round(v["found"] / v["total"], 3) if v["total"] else 1.0
    return cats


def evaluate(case_names: list[str]) -> dict:
    cases = [score_case(CASES_DIR / n) for n in case_names]
    tp = sum(c["true_positives"] for c in cases)
    fp = sum(c["false_positives"] for c in cases)
    total = sum(c["iocs_total"] for c in cases)
    found = sum(c["iocs_found"] for c in cases)
    cat_agg: dict[str, dict] = {}
    for c in cases:
        for cat, v in c["per_category"].items():
            a = cat_agg.setdefault(cat, {"total": 0, "found": 0})
            a["total"] += v["total"]; a["found"] += v["found"]
    for cat, v in cat_agg.items():
        v["recall"] = round(v["found"] / v["total"], 3) if v["total"] else 1.0
    return {
        "cases": cases,
        "overall": {
            "cases_evaluated": len(cases),
            "total_iocs": total,
            "iocs_found": found,
            "detections": tp + fp,
            "false_positives": fp,
            **_prf(found, fp, total - found),
            "per_category": cat_agg,
        },
    }


def main() -> None:
    if len(sys.argv) > 1:
        names = [Path(a).name for a in sys.argv[1:]]
    else:
        names = DEFAULT_CASES
    result = evaluate(names)
    o = result["overall"]

    print("SIFT-HUNTER — Deterministic Detection Evaluation (no LLM, no API key)")
    print("=" * 76)
    print(f"{'Case':<16}{'IOCs':>6}{'Found':>7}{'FP':>5}{'Precision':>11}{'Recall':>9}{'F1':>7}")
    print("-" * 76)
    for c in result["cases"]:
        m = c["metrics_all"]
        print(f"{c['case_id']:<16}{c['iocs_total']:>6}{c['iocs_found']:>7}{c['false_positives']:>5}"
              f"{m['precision']*100:>10.0f}%{m['recall']*100:>8.0f}%{m['f1']:>7.2f}")
    print("-" * 76)
    print(f"{'OVERALL':<16}{o['total_iocs']:>6}{o['iocs_found']:>7}{o['false_positives']:>5}"
          f"{o['precision']*100:>10.0f}%{o['recall']*100:>8.0f}%{o['f1']:>7.2f}")
    print("=" * 76)
    print("Per-category recall:")
    for cat, v in sorted(o["per_category"].items()):
        print(f"  {cat:<16} {v['found']}/{v['total']}  ({v['recall']*100:.0f}%)")
    print("-" * 76)
    for c in result["cases"]:
        miss = ", ".join(c["iocs_missed"]) or "none"
        print(f"  {c['case_id']}: deterministic-scoped recall {c['recall_deterministic_scoped']*100:.0f}%  | missed: {miss}")
    print("=" * 76)
    print(f"{o['detections']} detections, {o['false_positives']} false positives → "
          f"precision {o['precision']*100:.0f}%, recall {o['recall']*100:.0f}%, F1 {o['f1']:.2f}")

    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "evaluation.json").write_text(json.dumps(result, indent=2))
    print(f"Full results + SHA-256 chain of custody → {out_dir / 'evaluation.json'}")


if __name__ == "__main__":
    main()
