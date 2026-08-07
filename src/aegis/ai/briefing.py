"""Morning Jarvis briefing: overnight survivors as a ranked, plain-English queue.

After a 24/7 sweep you don't want to read raw JSON reports — you want a prioritized list:
what survived validation, how confident (cross-engine agreement), how much it's worth, and
where the PoC scaffold is. This scans the persisted reports and renders one Markdown digest,
ranked by corroboration then expected bounty. Deterministic — no LLM call, so the briefing
is reliable and free to regenerate.
"""

from __future__ import annotations

import glob
import json
import os
from datetime import UTC, datetime
from pathlib import Path


def _confirmed_rows(report: dict) -> list[dict]:
    out = []
    for row in report.get("vulnerabilities", []) or []:
        if (row.get("validation") or {}).get("verdict") == "confirmed":
            out.append(row)
    return out


def collect(report_dir: str | Path = "reports") -> tuple[list[dict], dict]:
    """Return (survivors, stats). Survivors are flattened confirmed findings with
    provenance, corroboration, reachability, and economics pulled from each report."""
    survivors: list[dict] = []
    scanned = 0
    for path in glob.glob(str(Path(report_dir) / "deepseek_*.json")):
        try:
            rep = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            continue
        scan = rep.get("scan") or {}
        repo = scan.get("repository") or Path(path).stem.replace("deepseek_", "")
        scanned += 1
        for row in _confirmed_rows(rep):
            a = row.get("json_answer") or {}
            enr = row.get("enrichment") or {}
            corr = row.get("corroboration") or {"count": 1, "engines": []}
            src = str(row.get("source") or "aegis:llm")
            origin = ("scanner" if ":tool:" in src else "skill" if ":skill:" in src else "llm")
            survivors.append({
                "repo": repo,
                "cwe": a.get("vulnerability_type", ""),
                "location": f"{a.get('file_path','')}:{a.get('line','')}",
                "summary": (a.get("summary") or "")[:200],
                "origin": origin,
                "engines": corr.get("engines", []),
                "corroboration": int(corr.get("count", 1)),
                "severity": (enr.get("cvss_band") or row.get("severity") or "medium"),
                "cvss": enr.get("cvss_score"),
                "bounty_min": enr.get("bounty_min"),
                "bounty_likely": enr.get("bounty_likely"),
                "remediation": (enr.get("remediation") or "")[:300],
                "commit": scan.get("commit", "")[:12],
            })
    survivors.sort(key=lambda f: (-f["corroboration"], -(f.get("bounty_likely") or 0)))
    stats = {"targets_scanned": scanned, "survivors": len(survivors),
             "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")}
    return survivors, stats


def render_markdown(survivors: list[dict], stats: dict) -> str:
    lines = [
        f"# ☀ Aegis overnight briefing — {stats['generated_at']}",
        "",
        f"**{stats['targets_scanned']}** targets scanned · "
        f"**{stats['survivors']}** confirmed survivor(s) (each needs human reproduction "
        f"before submission).",
        "",
    ]
    if not survivors:
        lines += ["No confirmed survivors overnight. On picked-over code this is the "
                  "expected, honest outcome — nothing fabricated to fill the page.", ""]
        return "\n".join(lines)
    for i, f in enumerate(survivors, 1):
        agree = (f"  ·  ✦ **{f['corroboration']} engines agree** "
                 f"({', '.join(f['engines'])})" if f["corroboration"] > 1 else
                 f"  ·  found by {f['origin']}")
        money = ""
        if f.get("bounty_likely"):
            money = f"  ·  ~${f['bounty_likely']:,} likely" + (
                f" (min ${f['bounty_min']:,})" if f.get("bounty_min") else "")
        cvss = f"  ·  CVSS {f['cvss']}" if f.get("cvss") else ""
        lines += [
            f"## {i}. {f['cwe']} — `{f['repo']}`",
            f"`{f['location']}`{agree}{money}{cvss}",
            "",
            f"{f['summary']}",
        ]
        if f.get("remediation"):
            lines.append(f"\n**Fix:** {f['remediation']}")
        lines.append("")
    return "\n".join(lines)


def build_briefing(report_dir: str | Path = "reports",
                   out_path: str | Path = "reports/briefing.md") -> dict:
    survivors, stats = collect(report_dir)
    md = render_markdown(survivors, stats)
    Path(out_path).write_text(md, encoding="utf-8")
    return {"survivors": len(survivors), "targets_scanned": stats["targets_scanned"],
            "path": str(out_path)}


def main(argv=None) -> int:
    report_dir = os.environ.get("AEGIS_REPORT_DIR", "reports")
    info = build_briefing(report_dir)
    print(f"briefing: {info['survivors']} survivor(s) across {info['targets_scanned']} "
          f"targets -> {info['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
