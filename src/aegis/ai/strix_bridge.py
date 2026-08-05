"""Arm's-length bridge to Strix (usestrix/strix) — an autonomous AI pentester.

Strix (Apache-2.0) is a peer agent: it runs code dynamically and validates findings with
real PoCs. Aegis invokes it as ONE more engine — like the scanners and skills — folding its
findings into the report so they run through Aegis's own citation validator + corroboration.
No Strix source is vendored; Aegis shells out to the installed CLI and reads its run output.

Heavyweight and OPT-IN (it drives its own LLM + Docker sandbox and costs real budget per
run), gated behind AEGIS_ALLOW_STRIX=1. Source-scan mode only here (`--target <local dir>`),
never a live third-party host — the same boundary the web lane and reproduction hold.

Point Strix at Aegis's model via the operator's env, e.g.:
    export STRIX_LLM=deepseek/deepseek-chat ; export LLM_API_KEY=<key>
"""

from __future__ import annotations

import csv
import os
import re
import subprocess
from pathlib import Path


def _resolve() -> str | None:
    from .tool_bridge import resolve_binary
    return resolve_binary(os.environ.get("AEGIS_STRIX_BIN", "strix"))


class StrixBridge:
    """Invoke the installed Strix CLI on a local target and ingest its findings."""

    def __init__(self, *, cmd_bin: str | None = None, runs_dir: str | Path = "strix_runs",
                 timeout: int = 3600) -> None:
        self._bin = cmd_bin or _resolve()
        self._runs = Path(runs_dir)
        self._timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self._bin) and os.environ.get("AEGIS_ALLOW_STRIX", "").strip() == "1"

    def run(self, target_path: str | Path, *, scan_mode: str = "standard",
            instruction: str = "") -> Path | None:
        """Run Strix source-scan on a LOCAL directory; return its run dir, or None."""
        if not self.enabled:
            return None
        argv = [self._bin, "-n", "--target", str(target_path), "--scan-mode", scan_mode]
        if instruction:
            argv += ["--instruction", instruction[:2000]]
        before = set(self._runs.glob("*")) if self._runs.is_dir() else set()
        try:
            subprocess.run(argv, capture_output=True, text=True, timeout=self._timeout,
                           check=False)
        except Exception:
            return None
        if not self._runs.is_dir():
            return None
        after = [d for d in self._runs.glob("*") if d.is_dir()]
        fresh = [d for d in after if d not in before] or after
        return max(fresh, key=lambda d: d.stat().st_mtime) if fresh else None

    def to_findings(self, run_dir: Path | None, *, repository: str = "") -> list[dict]:
        """Parse a Strix run dir's vulnerabilities into Aegis rows (unverified)."""
        if not run_dir or not Path(run_dir).is_dir():
            return []
        run_dir = Path(run_dir)
        rows: list[dict] = []
        csv_path = run_dir / "vulnerabilities.csv"
        entries: list[dict] = []
        if csv_path.is_file():
            try:
                entries = list(csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()))
            except Exception:
                entries = []
        for e in entries:
            vid = str(e.get("id") or "")
            title = str(e.get("title") or "strix-finding")
            sev = str(e.get("severity") or "medium").lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "medium"
            file_path = str(e.get("file") or "")
            line, detail = self._md_detail(run_dir, vid)
            rows.append({
                "json_answer": {
                    "vulnerability_type": title[:200],
                    "file_path": file_path,
                    "line": line,
                    "summary": title[:300],
                    "explanation": detail[:4000],
                },
                "severity": "medium" if sev == "info" else sev,
                "source": f"aegis:strix:{vid or 'finding'}",
                "validation_status": "unverified",
                "confidence": 0.0,
            })
        return rows

    @staticmethod
    def _md_detail(run_dir: Path, vid: str) -> tuple[int, str]:
        md = run_dir / "vulnerabilities" / f"{vid}.md"
        if not md.is_file():
            return 0, ""
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return 0, ""
        # first line number referenced in the finding (code_locations render as file:line)
        m = re.search(r":(\d{1,6})\b", text)
        line = int(m.group(1)) if m else 0
        # the Description section body, for the explanation
        desc = ""
        mm = re.search(r"## Description\s*\n+(.+?)(\n## |\Z)", text, re.S)
        if mm:
            desc = " ".join(mm.group(1).split())
        return line, desc[:4000]
