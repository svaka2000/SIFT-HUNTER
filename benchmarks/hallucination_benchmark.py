"""
Deterministic hallucination-detection benchmark - NO API key required.

This measures the *automated* hallucination detector
(`sift_hunter.core.hallucination_detector.verify_finding`) the same way a judge
would want to: feed it a labelled set of findings whose claimed IOCs are either
grounded in the tool output ("grounded") or fabricated ("hallucinated"), then
measure how often it flags the fabrications and how often it false-positives on
grounded claims.

It is intentionally adversarial - it includes near-miss IOCs (off-by-one IPs,
typo'd executables) and substring traps (an exe name that is a substring of a
real one) so the reported rates reflect genuine limitations rather than a rigged
100%. The numbers printed here are the *source of truth* for the detection-rate
table in docs/ACCURACY_REPORT.md.

Run:
    python -m benchmarks.hallucination_benchmark
"""
from __future__ import annotations

from dataclasses import dataclass

from sift_hunter.core.hallucination_detector import verify_finding
from sift_hunter.core.models import ConfidenceLevel, Finding, ToolExecution


@dataclass(frozen=True)
class Case:
    category: str
    label: str          # "grounded" | "hallucinated"
    description: str     # the agent's claim (entities extracted from here)
    excerpt: str         # raw_evidence_excerpt the agent cited
    corpus: str          # the raw tool output (the source of truth)


# Shared realistic tool outputs (the "source of truth" the detector checks against).
_MFT = (
    "MFTECmd v1.2 - EntryNumber,Name,Path,Created0x10,Created0x30\n"
    "1234,svchost_helper.exe,C:\\Users\\victim\\AppData\\Local\\Temp,2024-01-13,2024-01-15\n"
    "9,svchost.exe,C:\\Windows\\System32,2019-03-19,2019-03-19\n"
    "42,explorer.exe,C:\\Windows,2019-03-19,2019-03-19"
)
_NETSTAT = (
    "vol3 windows.netscan - Proto,Local,Foreign,State,Owner\n"
    "TCPv4,192.168.1.50:49152,198.51.100.44:4444,ESTABLISHED,svchost_helper.exe\n"
    "TCPv4,192.168.1.50:50100,10.0.0.5:443,ESTABLISHED,chrome.exe"
)
_REG = (
    "RECmd - HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
    "  WindowsHelper = C:\\Users\\victim\\AppData\\Local\\Temp\\svchost_helper.exe"
)
_PRESENT_SHA256 = "a3f5c9e1b7d2486f0c1e9a4b8d6f2031c5e7a9b1d3f50617283940a1b2c3d4e5"
_HASH = f"hashdump - svchost_helper.exe SHA256: {_PRESENT_SHA256}"


CASES: list[Case] = [
    # ── Executable names ────────────────────────────────────────────────
    Case("exe", "grounded", "svchost_helper.exe was dropped into the Temp directory",
         "1234,svchost_helper.exe", _MFT),
    Case("exe", "grounded", "explorer.exe is the legitimate shell process",
         "42,explorer.exe", _MFT),
    Case("exe", "hallucinated", "cobalt_implant.exe was injected into memory",
         "cobalt_implant.exe", _MFT),
    Case("exe", "hallucinated", "mimikatz_x64.exe was used to dump credentials",
         "mimikatz_x64.exe", _MFT),
    Case("exe", "hallucinated", "ransomware_lock.exe encrypted the user profile",
         "ransomware_lock.exe", _MFT),
    Case("exe", "hallucinated", "svchost_helperr.exe established persistence",  # typo near-miss
         "svchost_helperr.exe", _MFT),
    # substring trap: "host.exe" is a substring of "svchost.exe" - a known FN mode
    Case("exe", "hallucinated", "host.exe spawned a child process",
         "host.exe", _MFT),

    # ── IPv4 addresses ──────────────────────────────────────────────────
    Case("ip", "grounded", "C2 channel to 198.51.100.44 on port 4444",
         "198.51.100.44:4444", _NETSTAT),
    Case("ip", "grounded", "internal host 192.168.1.50 initiated the connection",
         "192.168.1.50:49152", _NETSTAT),
    Case("ip", "hallucinated", "second-stage beacon to 203.0.113.77",
         "203.0.113.77", _NETSTAT),
    Case("ip", "hallucinated", "exfiltration to 8.8.4.4 over DNS",
         "8.8.4.4", _NETSTAT),
    Case("ip", "hallucinated", "callback observed to 198.51.100.45",  # off-by-one near-miss
         "198.51.100.45", _NETSTAT),

    # ── Cryptographic hashes ────────────────────────────────────────────
    Case("hash", "grounded", f"dropper hash confirmed as {_PRESENT_SHA256}",
         _PRESENT_SHA256, _HASH),
    Case("hash", "hallucinated",
         "payload hash 0011223344556677889900aabbccddeeff00112233445566778899aabbccddee",
         "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee", _HASH),
    Case("hash", "hallucinated",
         "second-stage hash deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
         "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", _HASH),

    # ── Registry keys ───────────────────────────────────────────────────
    Case("registry", "grounded",
         "persistence via HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsHelper",
         "Run\\WindowsHelper", _REG),
    Case("registry", "hallucinated",
         "persistence via HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilPersist",
         "Run\\EvilPersist", _REG),
    Case("registry", "hallucinated",
         "service implanted at HKLM\\SYSTEM\\CurrentControlSet\\Services\\FakeSvcLoader",
         "Services\\FakeSvcLoader", _REG),

    # ── File paths (variable representation → treated as uncertain) ──────
    Case("path", "grounded", "malware staged at C:\\Users\\victim\\AppData\\Local\\Temp\\svchost_helper.exe",
         "C:\\Users\\victim\\AppData\\Local\\Temp\\svchost_helper.exe", _MFT),
    Case("path", "hallucinated", "loader dropped at C:\\Windows\\System32\\evil_dropper.dll",
         "C:\\Windows\\System32\\evil_dropper.dll", _MFT),
    Case("path", "hallucinated", "stage two written to C:\\ProgramData\\malware\\stage2.bin",
         "C:\\ProgramData\\malware\\stage2.bin", _MFT),
]


def _flagged(case: Case) -> bool:
    """True if the detector raised any signal (not a clean verdict) on this case."""
    finding = Finding(
        type="EXECUTION",
        title="benchmark finding",
        description=case.description,
        confidence=ConfidenceLevel.PROBABLE,
        raw_evidence_excerpt=case.excerpt,
        agent="disk_analyst",
    )
    te = ToolExecution(tool_name="benchmark_tool", command="bench", raw_output=case.corpus)
    result = verify_finding(finding, [te])
    return result.overall_verdict != "clean"


def run() -> dict:
    """Run the benchmark and return per-category + overall metrics."""
    categories = ["exe", "ip", "hash", "registry", "path"]
    metrics: dict = {}
    tot_h = tot_h_flag = tot_g = tot_g_flag = 0

    for cat in categories:
        cases = [c for c in CASES if c.category == cat]
        hall = [c for c in cases if c.label == "hallucinated"]
        grnd = [c for c in cases if c.label == "grounded"]
        h_flag = sum(1 for c in hall if _flagged(c))
        g_flag = sum(1 for c in grnd if _flagged(c))  # false positives
        metrics[cat] = {
            "n_hallucinated": len(hall),
            "detected": h_flag,
            "detection_rate": round(h_flag / len(hall), 3) if hall else None,
            "n_grounded": len(grnd),
            "false_positives": g_flag,
            "false_positive_rate": round(g_flag / len(grnd), 3) if grnd else None,
        }
        tot_h += len(hall); tot_h_flag += h_flag
        tot_g += len(grnd); tot_g_flag += g_flag

    metrics["overall"] = {
        "n_hallucinated": tot_h,
        "detected": tot_h_flag,
        "detection_rate": round(tot_h_flag / tot_h, 3) if tot_h else None,
        "n_grounded": tot_g,
        "false_positives": tot_g_flag,
        "false_positive_rate": round(tot_g_flag / tot_g, 3) if tot_g else None,
    }
    return metrics


_LABELS = {
    "exe": "Executable name not in tool output",
    "ip": "IP address not in tool output",
    "hash": "Cryptographic hash not in tool output",
    "registry": "Registry key not in tool output",
    "path": "File path not in tool output",
}


def main() -> None:
    m = run()
    print("SIFT-HUNTER - Automated Hallucination Detector Benchmark")
    print("=" * 68)
    print(f"{'Claim type':<40}{'Detect':>9}{'FP':>9}")
    print("-" * 68)
    for cat in ["exe", "ip", "hash", "registry", "path"]:
        d = m[cat]
        dr = f"{d['detection_rate']*100:.0f}%" if d["detection_rate"] is not None else "n/a"
        fp = f"{d['false_positive_rate']*100:.0f}%" if d["false_positive_rate"] is not None else "n/a"
        print(f"{_LABELS[cat]:<40}{dr:>9}{fp:>9}")
    print("-" * 68)
    o = m["overall"]
    print(f"{'OVERALL':<40}{o['detection_rate']*100:>8.0f}%{o['false_positive_rate']*100:>8.0f}%")
    print("=" * 68)
    print(f"{o['detected']}/{o['n_hallucinated']} fabrications flagged, "
          f"{o['false_positives']}/{o['n_grounded']} grounded claims false-flagged.")


if __name__ == "__main__":
    main()
