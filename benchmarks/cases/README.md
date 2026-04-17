# Benchmark Cases

Each benchmark case is a directory containing:
- `case.json` — metadata and expected findings
- `evidence/` — evidence files (or symlinks)
- `ground_truth.json` — expected findings with confidence levels

## Format

```json
{
  "case_id": "case001",
  "description": "Windows ransomware infection",
  "evidence_paths": ["evidence/disk.dd", "evidence/memory.dmp"],
  "expected_findings": [
    {
      "finding_type": "PERSISTENCE",
      "title": "Run key persistence",
      "confidence_min": "PROBABLE",
      "mitre_technique": "T1547.001",
      "must_contain": ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]
    }
  ]
}
```
