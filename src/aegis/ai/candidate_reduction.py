"""Deterministic candidate-reduction funnel.

The funnel suppresses scanner noise before expensive reasoning but never promotes a scanner hit
into a vulnerability. Suppression is intentionally conservative around credentials: deployment
and CI/IaC files are real attack surface, so credible secrets there survive unless the *filename*
clearly marks the content as an example/template/fixture.

Corroboration is counted by independent *evidence family*, not raw tool count. Two weak tools
that implement the same heuristic class must not bootstrap each other into a high-value survivor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_LOW_VALUE_RULES: dict[str, str] = {
    "B101": "assert-used (stripped under -O; not a vuln)",
    "B110": "try/except/pass (style, not exploitable alone)",
    "B112": "try/except/continue (style, not exploitable alone)",
    "B404": "import subprocess (import alone is not a sink)",
    "B603": "subprocess call without shell (needs taint to matter)",
    "B607": "partial executable path (hardening nit, not a vuln alone)",
    "B311": "stdlib random (only matters for crypto/token use)",
    "B322": "input() builtin (py2 legacy; n/a)",
    "B104": "bind all interfaces (deployment posture, not a code vuln candidate)",
    "B113": "requests without timeout (reliability hygiene, not a vuln)",
    "B103": "permissive file permissions (hardening nit)",
    "B413": "deprecated pyCrypto import (import alone is not a sink)",
    "B405": "xml.etree import (import alone is not a sink)",
    "B314": "xml.etree parse (hygiene unless untrusted XML is proven)",
    "B318": "xml.dom.minidom import (import alone is not a sink)",
    "B320": "lxml import (import alone is not a sink)",
    "B410": "lxml import (import alone is not a sink)",
    "B411": "xmlrpc import (import alone is not a sink)",
}

_REQUIRES_CORROBORATION: dict[str, str] = {
    "B608": "string-built SQL without taint proof",
    "B105": "hardcoded-password heuristic",
    "B106": "hardcoded-password heuristic",
    "B107": "hardcoded-password default-arg heuristic",
    "B108": "hardcoded temp path heuristic",
    "B310": "urllib open without taint proof",
    "B303": "weak-hash heuristic",
    "B324": "weak-hash heuristic",
    "B602": "subprocess shell=True without taint proof",
    "B605": "start process with a shell without taint proof",
    "B102": "exec() used without taint proof",
    "B307": "eval() used without taint proof",
    "B301": "pickle load without taint proof",
    "B506": "yaml.load without taint proof",
    "B202": "tarfile extract without taint proof (tar-slip needs a reachable attacker archive)",
    "B701": "jinja2 autoescape=false (XSS needs a reachable untrusted-output template)",
}
_CORROBORATION_MIN = 2
_STRONG_CONF = 0.85

# tools whose findings are weak on their own (high false-positive rate) — survive only when
# corroborated by a second engine or highly confident. njsscan fires on Math.random() and the
# literal word "username"; brakeman flags every interpolated where(...) as SQLi on mature Rails
# apps (discourse alone produced 262 brakeman-only "findings", ~all FPs). Both need corroboration.
_WEAK_TOOLS = {"njsscan", "brakeman"}

# checkov docker/IaC hygiene checks: real hardening advice, but not a candidate vulnerability
# hypothesis — suppressed by prefix so the whole CKV_DOCKER_* family collapses.
_LOW_VALUE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("CKV_DOCKER_", "container image hygiene (HEALTHCHECK/USER/tag), not a vuln"),
)

_SECRET_RULES = {"CWE-798"}
_SECRET_TOOLS = {"detect-secrets", "gitleaks"}
_BANDIT_SECRET_RULES = {"B105", "B106", "B107"}

_PLACEHOLDER_FILE = re.compile(
    r"(\.example$|\.sample$|\.template$|\.dist$|"
    r"(^|/)\.env\.(example|sample|template|dist)$|"
    r"(^|/)(examples?|samples?|fixtures?|mocks?)(/|$)|"
    r"\.(md|rst|txt)$)",
    re.IGNORECASE,
)

_PATH_CLASSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("test", re.compile(r"(^|/)_*(tests?|specs?)_*(/|$)|(_test|\.test|\.spec)\.", re.I)),
    ("bench", re.compile(r"(^|/)bench(es|mark|marks|marking)?(/|$)", re.I)),
    # example/sample/fixture/mock/demo/submission directory segments (segment must START with the
    # token, so `Example_Submissions/`, `examples/`, `sample-app/` match but a FILE like
    # `app.env.example` does not — that is handled as a placeholder secret, not a non-product path).
    ("example", re.compile(r"(^|/)(examples?|demos?|samples?|fixtures?|mocks?|"
                           r"submissions?)[^/]*(/|$)", re.I)),
    ("vendor", re.compile(r"(^|/)(vendor|third_party|node_modules|bower_components|"
                          r"forge-std|openzeppelin|lib/forge-std)(/|$)", re.I)),
    # minified/bundled/generated + browser-save archives (…_Files/) + solidity build output.
    ("generated", re.compile(r"[.-]min[.-]|[.-]min\.(js|css)$|\.bundle\.js$|"
                             r"(^|/)(dist|build|out|artifacts|coverage)(/|$)|"
                             r"_files?/|discord-export|_generated|_pb2|\.pb\.", re.I)),
    ("docs", re.compile(r"(^|/)docs?(/|$)|\.(md|rst)$|(^|/)readme", re.I)),
    # CI/deploy/build tooling: not the audited app/contract surface for a code/contract bounty.
    ("build", re.compile(r"(^|/)(certora|foundry|hardhat|truffle|scripts?|tools?|tooling|"
                         r"ci|deployments?)(/|$)|certora[_-]?build", re.I)),
    ("deploy", re.compile(r"(^|/)(deploy|\.github|k8s|helm|charts?|terraform)(/|$)|"
                          r"(^|/)docker-compose[^/]*\.ya?ml$|(^|/)dockerfile[^/]*$|\.tf$", re.I)),
    ("config", re.compile(r"\.(ya?ml|toml|ini|cfg|conf|json|env)$|(^|/)\.env", re.I)),
)

#: path classes that are not the product's runtime attack surface -> suppress by default.
#: deploy/build (CI, deploy scripts, certora/foundry/hardhat tooling) are out of scope for a
#: code/contract bounty — a subprocess/exec finding in a build script is not the audited bug.
_NONPRODUCT = {"test", "bench", "example", "vendor", "generated", "docs", "deploy", "build"}

_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.15}
_PATHCLASS_WEIGHT = {"source": 1.0, "config": 0.8, "deploy": 0.8}


def _normalize_path(path: str) -> str:
    """Normalize separators without destroying meaningful leading dot-directories."""
    p = str(path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def path_class(path: str) -> str:
    p = _normalize_path(path)
    if not p:
        return "source"
    for name, rx in _PATH_CLASSES:
        if rx.search(p):
            return name
    return "source"


def _tool_of(row: dict) -> str:
    src = str(row.get("source") or "")
    return src.split("aegis:tool:", 1)[1] if "aegis:tool:" in src else (row.get("tool") or "?")


def _rule_of(row: dict) -> str:
    md = row.get("scanner_metadata") or {}
    rid = md.get("rule_id") or md.get("cwe")
    if rid:
        return str(rid)
    vt = str((row.get("json_answer") or {}).get("vulnerability_type") or "?")
    return vt.split(":", 1)[0].strip() if vt.startswith("CKV") else vt


def _cwe_of(row: dict) -> str:
    md = row.get("scanner_metadata") or {}
    for v in (md.get("cwe"), (row.get("json_answer") or {}).get("vulnerability_type")):
        m = re.search(r"CWE-\d+", str(v or ""), re.I)
        if m:
            return m.group(0).upper()
    return ""


@dataclass
class Candidate:
    tool: str
    rule: str
    cwe: str
    path: str
    line: int
    severity: str
    confidence: float
    summary: str
    path_class: str
    kept: bool = True
    reason: str = ""
    corroborators: int = 1
    score: float = 0.0
    raw: dict = field(default_factory=dict, repr=False, compare=False)

    def public(self) -> dict:
        return {"tool": self.tool, "rule": self.rule, "cwe": self.cwe, "path": self.path,
                "line": self.line, "severity": self.severity, "confidence": self.confidence,
                "summary": self.summary, "path_class": self.path_class, "kept": self.kept,
                "reason": self.reason, "corroborators": self.corroborators, "score": self.score}

    @property
    def locus(self) -> tuple[str, int]:
        return (self.path, self.line // 5)

    @property
    def family_key(self) -> tuple[str, str]:
        return (self.cwe or self.rule, self.path_class)


def _evidence_family(c: Candidate) -> str:
    """Return the independent-method family used for corroboration counting.

    Bandit's B105/B106/B107 hardcoded-string checks and detect-secrets' keyword/entropy checks
    are both weak secret heuristics. Treating them as two independent confirmations caused
    security vocabulary constants such as ``secret_candidate`` to survive the self-hunt.
    Gitleaks remains a separate signature-driven family.
    """
    tool = c.tool.casefold()
    if tool == "detect-secrets" or (tool == "bandit" and c.rule in _BANDIT_SECRET_RULES):
        return "secret-heuristic"
    if tool == "gitleaks":
        return "secret-signature"
    if tool == "bandit" and c.rule == "B608":
        return "sql-string-heuristic"
    return f"{tool}:{c.rule or c.cwe}"


@dataclass
class Family:
    key: str
    cwe: str
    path_class: str
    count: int
    score: float
    tools: list[str] = field(default_factory=list)
    example_path: str = ""
    example_summary: str = ""


@dataclass
class Reduction:
    raw: int
    survivors: list[Candidate] = field(default_factory=list)
    suppressed: list[Candidate] = field(default_factory=list)
    families: list[Family] = field(default_factory=list)
    funnel: dict = field(default_factory=dict)

    @property
    def survivor_rows(self) -> list[dict]:
        return [c.raw for c in self.survivors if c.raw]

    def summary(self) -> dict:
        return {"funnel": self.funnel, "survivors": len(self.survivors),
                "families": len(self.families),
                "top_families": [f.__dict__ for f in self.families[:12]]}

    def funnel_lines(self) -> list[str]:
        f = self.funnel
        order = ["raw", "deduped", "drop_dependency_advisory", "drop_non_product_path",
                 "drop_low_value_rule", "drop_weak_single_engine", "drop_placeholder_secret",
                 "survivors", "families"]
        return [f"  {k:26} {f.get(k, 0)}" for k in order if k in f]


def _to_candidate(row: dict) -> Candidate:
    ja = row.get("json_answer") or {}
    try:
        line = int(ja.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    try:
        confidence = float(row.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return Candidate(
        tool=_tool_of(row), rule=_rule_of(row), cwe=_cwe_of(row),
        path=_normalize_path(ja.get("file_path") or ""),
        line=line, severity=str(row.get("severity") or "medium").lower(),
        confidence=confidence,
        summary=str(ja.get("summary") or ja.get("vulnerability_type") or ""),
        path_class="", raw=row)


_ADVISORY_ID = re.compile(r"^(CVE-\d{4}-\d+|GHSA-\w{4}-\w{4}-\w{4})$", re.I)
_DEP_TOOLS = {"trivy", "grype", "osv-scanner", "osv", "retire.js", "retire"}
_DEP_MANIFEST = re.compile(
    r"(requirements[^/]*\.txt|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|"
    r"Gemfile\.lock|go\.sum|poetry\.lock|Cargo\.lock|composer\.lock))$", re.I)


def _is_dependency_advisory(c: Candidate) -> bool:
    """A scanner reporting a known CVE/GHSA in a third-party dependency.

    These are real but out of scope for SOURCE-CODE review: public, in code the target does not
    own, and — corroborated by trivy+grype+osv — they otherwise top the survivor list and bury the
    target's own bugs (observed: 17 aiohttp CVEs ranking above every contract finding). Suppressed
    from survivors; retained in ``suppressed`` for audit.
    """
    if _ADVISORY_ID.match((c.rule or "").strip()):
        return True
    return c.tool in _DEP_TOOLS and bool(_DEP_MANIFEST.search(c.path or ""))


def _suppression_reason(c: Candidate) -> str:
    if _is_dependency_advisory(c):
        return (f"dependency-advisory:{c.rule or c.tool} (known CVE in a third-party "
                "dependency; out of scope for source-code review)")
    is_secret = c.cwe in _SECRET_RULES or c.tool in _SECRET_TOOLS
    if c.path_class in _NONPRODUCT:
        # deploy/build tooling is non-product for CODE findings (a subprocess/exec in a build
        # script is not the audited bug) — but a credible SECRET in a deploy/IaC manifest IS real
        # attack surface, so let secrets there fall through to the placeholder-file check.
        if not (is_secret and c.path_class in ("deploy", "build")):
            return f"non-product-path:{c.path_class}"
    if c.rule in _LOW_VALUE_RULES:
        return f"low-value-rule:{c.rule} ({_LOW_VALUE_RULES[c.rule]})"
    for prefix, why in _LOW_VALUE_PREFIXES:
        if c.rule.startswith(prefix):
            return f"low-value-rule:{prefix}* ({why})"

    if c.cwe in _SECRET_RULES or c.tool in _SECRET_TOOLS:
        if _PLACEHOLDER_FILE.search(c.path):
            return "placeholder/example secret (not a live credential claim)"

    corroborated = c.corroborators >= _CORROBORATION_MIN
    strong = c.confidence >= _STRONG_CONF
    if not corroborated and not strong:
        if c.rule in _REQUIRES_CORROBORATION:
            return (f"weak-single-engine:{c.rule} "
                    f"({_REQUIRES_CORROBORATION[c.rule]}; needs independent corroboration)")
        if c.tool == "detect-secrets":
            return "weak-single-engine:detect-secrets-unverified (needs independent corroboration)"
        # high-FP tools (njsscan, brakeman) survive only when corroborated or highly confident.
        if c.tool in _WEAK_TOOLS:
            return f"weak-single-engine:{c.tool} (high-FP tool; needs corroboration)"
    return ""


def _score(c: Candidate) -> float:
    base = _SEVERITY_WEIGHT.get(c.severity, 0.5) * (0.5 + 0.5 * min(1.0, max(0.0, c.confidence)))
    base *= _PATHCLASS_WEIGHT.get(c.path_class, 0.55)
    base += min(0.30, 0.15 * (c.corroborators - 1))
    return round(base, 4)


def reduce_candidates(rows: list[dict]) -> Reduction:
    raw = len(rows)
    cands = [_to_candidate(r) for r in rows]
    for c in cands:
        c.path_class = path_class(c.path)

    seen: set[tuple] = set()
    deduped: list[Candidate] = []
    for c in cands:
        key = (c.tool, c.rule, c.path, c.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)

    locus_families: dict[tuple, set[str]] = {}
    for c in deduped:
        locus_families.setdefault(c.locus, set()).add(_evidence_family(c))
    for c in deduped:
        c.corroborators = len(locus_families.get(c.locus, {_evidence_family(c)}))

    survivors: list[Candidate] = []
    suppressed: list[Candidate] = []
    for c in deduped:
        reason = _suppression_reason(c)
        if reason:
            c.kept, c.reason = False, reason
            suppressed.append(c)
        else:
            c.score = _score(c)
            survivors.append(c)

    survivors.sort(key=lambda c: c.score, reverse=True)

    fam: dict[tuple, Family] = {}
    for c in survivors:
        k = c.family_key
        if k not in fam:
            fam[k] = Family(key=str(k[0]), cwe=c.cwe, path_class=k[1], count=0, score=0.0,
                            example_path=c.path, example_summary=c.summary)
        f = fam[k]
        f.count += 1
        f.score = max(f.score, c.score)
        if c.tool not in f.tools:
            f.tools.append(c.tool)
    families = sorted(fam.values(), key=lambda f: (f.score, f.count), reverse=True)

    cats: dict[str, int] = {}
    for c in suppressed:
        if c.reason.startswith("dependency-advisory"):
            cat = "drop_dependency_advisory"
        elif c.reason.startswith("non-product"):
            cat = "drop_non_product_path"
        elif c.reason.startswith("low-value"):
            cat = "drop_low_value_rule"
        elif c.reason.startswith("weak-single-engine"):
            cat = "drop_weak_single_engine"
        else:
            cat = "drop_placeholder_secret"
        cats[cat] = cats.get(cat, 0) + 1
    funnel = {"raw": raw, "deduped": len(deduped), **cats,
              "survivors": len(survivors), "families": len(families)}
    return Reduction(raw=raw, survivors=survivors, suppressed=suppressed,
                     families=families, funnel=funnel)
