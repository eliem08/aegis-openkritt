"""Real OSS security scanners Aegis invokes (arm's-length) and folds into its pipeline.

Unlike LLM skills, these are deterministic static-analysis tools that actually find
bugs — Semgrep, Gitleaks, Bandit, Slither (contracts), njsscan, Trivy. Aegis invokes
the INSTALLED binary on a local checkout and ingests its JSON output as candidates;
it does not vendor any tool's source. Invoking a separate process is outside every
tool's copyleft (including Slither's AGPL) — Aegis only reads their factual findings.

Each tool declares how it's invoked (a command template over {target}), which lane it
serves, and an original parser mapping its native JSON to Aegis finding rows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str                 # executable to look up on PATH
    lanes: tuple[str, ...]      # "code" | "contract" | "secrets" | "deps"
    cmd: str                    # command template, {target} substituted
    license: str
    parse: Callable[[dict | list], list[dict]]   # native output -> Aegis rows


def _row(source, vtype, path, line, summary, severity="medium", detail=""):
    sev = str(severity or "medium").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    return {
        "json_answer": {"vulnerability_type": str(vtype)[:200], "file_path": str(path or ""),
                        "line": int(line or 0) if str(line or "").isdigit() else 0,
                        "summary": str(summary or "")[:300], "explanation": str(detail or "")[:4000]},
        "severity": "medium" if sev == "info" else sev,
        "source": f"aegis:tool:{source}",
        "validation_status": "unverified", "confidence": 0.0,
    }


def _parse_semgrep(data) -> list[dict]:
    rows = []
    for r in (data or {}).get("results", []) if isinstance(data, dict) else []:
        extra = r.get("extra", {})
        sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
            str(extra.get("severity", "")).upper(), "medium")
        rows.append(_row("semgrep", r.get("check_id", "semgrep-finding"), r.get("path"),
                         (r.get("start") or {}).get("line"), extra.get("message", ""), sev,
                         extra.get("message", "")))
    return rows


def _parse_gitleaks(data) -> list[dict]:
    items = data if isinstance(data, list) else (data or {}).get("findings", [])
    return [_row("gitleaks", f"secret: {i.get('RuleID') or i.get('Description','leak')}",
                 i.get("File"), i.get("StartLine"), i.get("Description", "hardcoded secret"),
                 "high") for i in (items or [])]


def _parse_bandit(data) -> list[dict]:
    rows = []
    for r in (data or {}).get("results", []) if isinstance(data, dict) else []:
        sev = str(r.get("issue_severity", "medium")).lower()
        rows.append(_row("bandit", r.get("test_id", "bandit"), r.get("filename"),
                         r.get("line_number"), r.get("issue_text", ""), sev,
                         r.get("issue_text", "")))
    return rows


def _parse_slither(data) -> list[dict]:
    rows = []
    dets = ((data or {}).get("results") or {}).get("detectors", []) if isinstance(data, dict) else []
    for d in dets:
        impact = {"High": "high", "Medium": "medium", "Low": "low"}.get(d.get("impact"), "medium")
        elems = d.get("elements") or [{}]
        loc = (elems[0].get("source_mapping") or {})
        rows.append(_row("slither", d.get("check", "slither"),
                         (loc.get("filename_relative") or loc.get("filename_short") or ""),
                         (loc.get("lines") or [0])[0], d.get("description", ""), impact,
                         d.get("description", "")))
    return rows


def _parse_njsscan(data) -> list[dict]:
    rows = []
    sec = (data or {}).get("nodejs", {}) if isinstance(data, dict) else {}
    for rule, body in sec.items():
        for f in body.get("files", []):
            rows.append(_row("njsscan", rule, f.get("file_path"),
                             (f.get("match_lines") or [0])[0],
                             body.get("metadata", {}).get("description", rule), "medium"))
    return rows


def _parse_trivy(data) -> list[dict]:
    rows = []
    for res in (data or {}).get("Results", []) if isinstance(data, dict) else []:
        for v in res.get("Vulnerabilities", []) or []:
            rows.append(_row("trivy", f"{v.get('VulnerabilityID','CVE')} in {v.get('PkgName','')}",
                             res.get("Target"), 0, v.get("Title", ""),
                             str(v.get("Severity", "medium")).lower(), v.get("Description", "")))
    return rows


TOOLS: tuple[Tool, ...] = (
    Tool("semgrep", "semgrep", ("code",),
         "semgrep --config auto --json --quiet {target}", "LGPL-2.1 (engine)/MIT (rules)",
         _parse_semgrep),
    Tool("gitleaks", "gitleaks", ("secrets",),
         "gitleaks detect --source {target} --report-format json --report-path -", "MIT",
         _parse_gitleaks),
    Tool("bandit", "bandit", ("code",),
         "bandit -r {target} -f json -q", "Apache-2.0", _parse_bandit),
    Tool("slither", "slither", ("contract",),
         "slither {target} --json -", "AGPL-3.0 (invoked, not vendored)", _parse_slither),
    Tool("njsscan", "njsscan", ("code",),
         "njsscan --json {target}", "LGPL-3.0 (invoked)", _parse_njsscan),
    Tool("trivy", "trivy", ("deps", "secrets"),
         "trivy fs --format json --quiet {target}", "Apache-2.0", _parse_trivy),
)


def tools_for(lane: str) -> list[Tool]:
    return [t for t in TOOLS if lane in t.lanes]
