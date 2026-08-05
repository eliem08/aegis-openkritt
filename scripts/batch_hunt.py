"""Drive Aegis across a batch of in-scope code targets; collect confirmed survivors.

Each target runs the full contract/repo lane (clone -> scanners -> ensemble generator ->
hardened validator -> PoC scaffold) in its own subprocess, so one target's failure never
kills the batch. Only CONFIRMED findings are surfaced — everything else is noise we drop.
Read-only source review of public repos; nothing is submitted.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PY = Path(".venv/Scripts/python.exe")
CORPUS = "reports/contract_corpus_0xsimao.jsonl"

# Fresh (unscanned), critical-floor, less-audited targets — highest EV first.
# WordPress-plugin PHP surface: access-control/IDOR-dominant, model-findable.
BATCH = [
    ("mainwp/mainwp", "wp-plugin"),
    ("mainwp/mainwp-child", "wp-plugin"),
    ("WordPoints/wordpoints", "wp-plugin"),
    ("hyperledger/fabric-chaincode-node", "chaincode"),
]


def run_one(repo: str, files: int = 12, samples: int = 3) -> dict:
    import os
    env = dict(os.environ, AEGIS_KNOWLEDGE_CORPUS=CORPUS)
    handle = repo.split("/")[0]
    proc = subprocess.run(
        [str(PY), "-m", "aegis.ai.hunt_repo", repo,
         "--files", str(files), "--samples", str(samples), "--handle", handle],
        capture_output=True, text=True, env=env, encoding="utf-8", errors="replace",
    )
    slug = "deepseek_" + repo.replace("/", "_") + ".json"
    report = Path("reports") / slug
    confirmed = []
    if report.is_file():
        try:
            d = json.loads(report.read_text(encoding="utf-8"))
            for v in d.get("vulnerabilities", []):
                if (v.get("validation", {}) or {}).get("verdict") == "confirmed":
                    j = v.get("json_answer", {})
                    confirmed.append({"type": j.get("vulnerability_type"),
                                      "where": f"{j.get('file_path')}:{j.get('line')}",
                                      "summary": j.get("summary")})
        except Exception as e:
            return {"repo": repo, "error": f"report parse: {e}"}
    tail = "\n".join(proc.stdout.splitlines()[-3:])
    return {"repo": repo, "confirmed": confirmed, "rc": proc.returncode, "tail": tail}


def main() -> int:
    results = []
    for repo, kind in BATCH:
        print(f"\n===== HUNT {repo} ({kind}) =====", flush=True)
        r = run_one(repo)
        results.append(r)
        c = r.get("confirmed", [])
        print(f"  -> confirmed: {len(c)}", flush=True)
        for f in c:
            print(f"     [{f['type']}] {f['where']}  {f['summary']}", flush=True)
        if r.get("error"):
            print(f"  -> ERROR {r['error']}", flush=True)
    total = sum(len(r.get("confirmed", [])) for r in results)
    print(f"\n===== BATCH DONE: {total} confirmed across {len(BATCH)} targets =====", flush=True)
    Path("reports/batch_hunt_summary.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
