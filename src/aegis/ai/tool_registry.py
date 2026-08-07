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


def _row(source, vtype, path, line, summary, severity="medium", detail="", *,
         metadata=None, confidence: float = 0.0):
    """Normalize a scanner observation without promoting it to a confirmed finding.

    ``metadata`` carries deterministic provenance used by the carpet sweep to rank
    source-to-sink findings above pattern-only warnings. It must never contain the raw
    secret value or other sensitive scanner output.
    """
    sev = str(severity or "medium").lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "medium"
    try:
        conf = min(1.0, max(0.0, float(confidence)))
    except (TypeError, ValueError):
        conf = 0.0
    safe_metadata = {}
    if isinstance(metadata, dict):
        for key in ("rule_id", "cwe", "class", "category", "confidence_label",
                    "precision", "validation", "secret_type", "verified"):
            value = metadata.get(key)
            if isinstance(value, (str, int, float, bool)) or value is None:
                safe_metadata[key] = value
    return {
        "json_answer": {"vulnerability_type": str(vtype)[:200], "file_path": str(path or ""),
                        "line": int(line or 0) if str(line or "").isdigit() else 0,
                        "summary": str(summary or "")[:300], "explanation": str(detail or "")[:4000]},
        "severity": "medium" if sev == "info" else sev,
        "source": f"aegis:tool:{source}",
        "validation_status": "unverified", "confidence": conf,
        "scanner_metadata": safe_metadata,
    }


def _parse_semgrep(data) -> list[dict]:
    rows = []
    confidence_map = {"HIGH": 0.90, "MEDIUM": 0.70, "LOW": 0.40}
    for r in (data or {}).get("results", []) if isinstance(data, dict) else []:
        extra = r.get("extra", {})
        sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
            str(extra.get("severity", "")).upper(), "medium")
        # Prefer the rule's CWE metadata over the raw (path-prefixed) check_id, so a hit
        # reads "CWE-434" not "src.aegis.ai.rules.aegis-php-upload-...".
        md = extra.get("metadata", {}) or {}
        cwe = md.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        rule_id = str(r.get("check_id", "semgrep-finding"))
        confidence_label = str(md.get("confidence", "")).upper()
        confidence = confidence_map.get(
            confidence_label, {"high": 0.80, "medium": 0.62, "low": 0.42}[sev])
        vtype = cwe or md.get("class") or rule_id.split(".")[-1]
        rows.append(_row(
            "semgrep", vtype, r.get("path"), (r.get("start") or {}).get("line"),
            extra.get("message", ""), sev, extra.get("message", ""),
            confidence=confidence,
            metadata={
                "rule_id": rule_id, "cwe": cwe, "class": md.get("class"),
                "category": md.get("category"), "confidence_label": confidence_label or None,
                "precision": md.get("precision"), "validation": md.get("validation"),
            },
        ))
    return rows


def _parse_gitleaks(data) -> list[dict]:
    items = data if isinstance(data, list) else (data or {}).get("findings", [])
    rows = []
    for item in items or []:
        rule_id = item.get("RuleID") or item.get("Description", "leak")
        rows.append(_row(
            "gitleaks", "CWE-798", item.get("File"), item.get("StartLine"),
            f"Potential hardcoded secret ({rule_id})", "high",
            "Potential secret detected; the raw value is intentionally not retained.",
            confidence=0.85,
            metadata={"rule_id": str(rule_id), "cwe": "CWE-798",
                      "class": "hardcoded-secret", "precision": "high",
                      "validation": "secret-review", "secret_type": str(rule_id)},
        ))
    return rows


def _parse_detect_secrets(data) -> list[dict]:
    """detect-secrets baseline JSON -> redacted Aegis observations.

    The baseline contains hashes and plugin metadata. Aegis keeps only type/path/line and
    verification state; it never copies a candidate secret or its hash into reports.
    """
    if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
        return []
    rows = []
    for path, findings in data["results"].items():
        for finding in findings or []:
            if not isinstance(finding, dict):
                continue
            secret_type = str(finding.get("type") or "potential secret")
            verified = bool(finding.get("is_verified"))
            rows.append(_row(
                "detect-secrets", "CWE-798", path, finding.get("line_number"),
                f"Potential hardcoded secret ({secret_type})",
                "high" if verified else "medium",
                "Potential secret detected; the raw value and hash are intentionally omitted.",
                confidence=0.95 if verified else 0.68,
                metadata={"rule_id": secret_type, "cwe": "CWE-798",
                          "class": "hardcoded-secret", "precision": "high" if verified else "medium",
                          "validation": "secret-review", "secret_type": secret_type,
                          "verified": verified},
            ))
    return rows


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


# njsscan's low-precision "pattern-only" rules: they fire on a shape (a regex, a ===, a
# conditional) and ASSUME the input is attacker-controlled. On framework/compiler/library code
# that assumption is almost always wrong (developer config, compiler source, internal state),
# so they produce near-pure false positives. Drop them; keep njsscan's real sinks (injection,
# hardcoded secrets, dangerous APIs).
_NJSSCAN_NOISE = frozenset({
    "regex_dos", "node_timing_attack", "node_logic_bypass",
})


def _parse_njsscan(data) -> list[dict]:
    rows = []
    sec = (data or {}).get("nodejs", {}) if isinstance(data, dict) else {}
    for rule, body in sec.items():
        if rule in _NJSSCAN_NOISE:
            continue                      # skip pattern-only rules that FP on framework code
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


def _parse_brakeman(data) -> list[dict]:
    """Brakeman (Rails SAST) JSON -> rows. warnings[] with confidence High/Medium/Weak."""
    rows = []
    warns = (data or {}).get("warnings", []) if isinstance(data, dict) else []
    conf = {"High": "high", "Medium": "medium", "Weak": "low"}
    for w in warns:
        rows.append(_row("brakeman", w.get("warning_type", "brakeman"), w.get("file"),
                         w.get("line"), w.get("message", ""),
                         conf.get(str(w.get("confidence")), "medium"),
                         f"{w.get('message','')} ({w.get('link','')})"))
    return rows


def _parse_gosec(data) -> list[dict]:
    """gosec (Go SAST) JSON -> rows. Issues[] with severity HIGH/MEDIUM/LOW."""
    rows = []
    for i in (data or {}).get("Issues", []) if isinstance(data, dict) else []:
        rows.append(_row("gosec", f"{i.get('rule_id','')}: {i.get('cwe',{}).get('id','') if isinstance(i.get('cwe'),dict) else ''}".strip(": "),
                         i.get("file"), i.get("line"), i.get("details", ""),
                         str(i.get("severity", "medium")).lower(), i.get("details", "")))
    return rows


def _parse_osv(data) -> list[dict]:
    """osv-scanner (Google, dependency vulns) JSON -> rows. results[].packages[].vulnerabilities[]."""
    rows = []
    for res in (data or {}).get("results", []) if isinstance(data, dict) else []:
        path = (res.get("source") or {}).get("path", "")
        for pkg in res.get("packages", []) or []:
            name = (pkg.get("package") or {}).get("name", "")
            for v in pkg.get("vulnerabilities", []) or []:
                rows.append(_row("osv-scanner", f"{v.get('id','vuln')} in {name}", path, 0,
                                 v.get("summary") or (v.get("details", "") or "")[:200], "high",
                                 v.get("details", "")))
    return rows


def _parse_checkov(data) -> list[dict]:
    """checkov (IaC security) JSON -> rows. Handles the single-framework dict and the
    multi-framework list form; reads results.failed_checks[]."""
    rows = []
    frames = data if isinstance(data, list) else [data]
    for fr in frames:
        if not isinstance(fr, dict):
            continue
        for c in ((fr.get("results") or {}).get("failed_checks", []) or []):
            lr = c.get("file_line_range") or [0]
            sev = str(c.get("severity") or "medium").lower()
            rows.append(_row("checkov", f"{c.get('check_id','')}: {c.get('check_name','')}",
                             c.get("file_path"), lr[0] if lr else 0,
                             c.get("check_name", ""), sev if sev in
                             ("critical", "high", "medium", "low") else "medium",
                             str(c.get("guideline") or "")))
    return rows


def _parse_grype(data) -> list[dict]:
    """grype (Anchore SCA) JSON -> rows. matches[].vulnerability + artifact locations."""
    rows = []
    for m in (data or {}).get("matches", []) if isinstance(data, dict) else []:
        v = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        locs = art.get("locations") or [{}]
        rows.append(_row("grype", f"{v.get('id','vuln')} in {art.get('name','')}",
                         (locs[0] or {}).get("path", ""), 0,
                         v.get("description") or f"{art.get('name','')} {art.get('version','')}",
                         str(v.get("severity", "medium")).lower(), v.get("description", "")))
    return rows


def _parse_psalm(data) -> list[dict]:
    """Psalm --taint-analysis (PHP) JSON -> rows. Array of issues with taint types."""
    items = data if isinstance(data, list) else (data or {}).get("issues", [])
    sev = {"error": "high", "warning": "medium", "info": "low"}
    rows = []
    for i in items or []:
        rows.append(_row("psalm", i.get("type", "psalm"), i.get("file_name") or i.get("file_path"),
                         i.get("line_from") or i.get("line"), i.get("message", ""),
                         sev.get(str(i.get("severity")).lower(), "medium"), i.get("snippet", "")))
    return rows


def _parse_mythril(data) -> list[dict]:
    """Mythril (Solidity symbolic execution) JSON -> rows. issues[] with SWC ids."""
    rows = []
    issues = (data or {}).get("issues", []) if isinstance(data, dict) else []
    for i in issues:
        rows.append(_row("mythril", f"{i.get('swcID') or i.get('swc-id','SWC')}: {i.get('title','')}",
                         i.get("filename"), i.get("lineno"), i.get("description", ""),
                         str(i.get("severity", "medium")).lower(), i.get("description", "")))
    return rows


def _parse_retirejs(data) -> list[dict]:
    """retire.js (JS dependency vulns) JSON -> rows. data[].results[].vulnerabilities[]."""
    rows = []
    for f in (data or {}).get("data", []) if isinstance(data, dict) else []:
        for res in f.get("results", []) or []:
            comp = f"{res.get('component','')}@{res.get('version','')}"
            for v in res.get("vulnerabilities", []) or []:
                ident = v.get("identifiers") or {}
                summary = ident.get("summary") or (v.get("info") or [""])[0]
                rows.append(_row("retire.js", f"{comp}: {ident.get('CVE',[''])[0] if ident.get('CVE') else 'vuln'}",
                                 f.get("file"), 0, summary, str(v.get("severity", "medium")).lower(),
                                 summary))
    return rows


TOOLS: tuple[Tool, ...] = (
    Tool("semgrep", "semgrep", ("code",),
         # bundled offline rules ({rules}) so PHP/Ruby/etc. are covered without the registry
         # (unreachable offline); --timeout caps per-rule time so semgrep-core can't hang.
         # Speed on big repos: skip heavy non-source trees + huge/generated files so a 40M
         # monorepo doesn't blow the wall-clock timeout (the carpet-sweep TimeoutExpired bug).
         # scan everything the target wrote (no size cap, no per-rule timeout); only skip
         # node_modules/vendor/.git (third-party deps + VCS — not the target's own code).
         "semgrep --config {rules} --json --quiet --timeout 0 "
         "--exclude node_modules --exclude vendor --exclude .git --error {target}",
         "LGPL-2.1 (engine) / Aegis rules", _parse_semgrep),
    Tool("gitleaks", "gitleaks", ("secrets",),
         # --no-git scans the working tree (current code) instead of the whole git history —
         # far faster on big repos, and we want secrets in the code, not old commits.
         "gitleaks detect --no-git --source {target} --report-format json --report-path -", "MIT",
         _parse_gitleaks),
    Tool("detect-secrets", "detect-secrets", ("secrets",),
         # Offline only: --no-verify prevents provider/network verification. --all-files scans
         # the checkout even when the shallow clone has unusual tracking metadata.
         "detect-secrets scan {target} --all-files --no-verify",
         "Apache-2.0", _parse_detect_secrets),
    Tool("bandit", "bandit", ("code",),
         "bandit -r {target} -f json -q", "Apache-2.0", _parse_bandit),
    Tool("slither", "slither", ("contract",),
         "slither {target} --json -", "AGPL-3.0 (invoked, not vendored)", _parse_slither),
    Tool("njsscan", "njsscan", ("code",),
         "njsscan --json {target}", "LGPL-3.0 (invoked)", _parse_njsscan),
    Tool("trivy", "trivy", ("deps", "secrets"),
         "trivy fs --format json --quiet {target}", "Apache-2.0", _parse_trivy),
    # High-star additions filling real language gaps (Ruby/Rails, Go) + universal SCA/IaC.
    Tool("brakeman", "brakeman", ("code",),
         "brakeman -f json -q {target}", "MIT (~7k*)", _parse_brakeman),
    Tool("gosec", "gosec", ("code",),
         "gosec -fmt=json -quiet -no-fail {target}/...", "Apache-2.0 (~8k*)", _parse_gosec),
    Tool("osv-scanner", "osv-scanner", ("deps",),
         "osv-scanner --format json -r {target}", "Apache-2.0 (~6k*)", _parse_osv),
    Tool("checkov", "checkov", ("deps",),
         "checkov -d {target} -o json --compact --quiet", "Apache-2.0 (~7k*)", _parse_checkov),
    Tool("grype", "grype", ("deps",),
         "grype dir:{target} -o json", "Apache-2.0 (~8k*)", _parse_grype),
    Tool("psalm", "psalm", ("code",),
         # {psalmcfg} is a per-scan psalm.xml (projectFiles=target + WordPress stubs). Stubs
         # must be configured in XML, NOT via a --stubs flag (which psalm rejects, so it used
         # to bail in 0.1s and never run).
         "psalm --config={psalmcfg} --taint-analysis --output-format=json --no-progress",
         "MIT (~5k*)", _parse_psalm),
    Tool("mythril", "myth", ("contract",),
         "myth analyze {target} -o json", "MIT (~4k*)", _parse_mythril),
    Tool("retire.js", "retire", ("deps",),
         "retire --outputformat json --path {target}", "Apache-2.0 (~4k*)", _parse_retirejs),
)


def tools_for(lane: str) -> list[Tool]:
    return [t for t in TOOLS if lane in t.lanes]
