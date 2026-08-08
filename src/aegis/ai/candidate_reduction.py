"""Deterministic candidate-reduction funnel.

Turns *hundreds of raw scanner rows* into a *small, ranked set of hypothesis families*
BEFORE any expensive AI analysis. It makes zero LLM calls and is fully deterministic, so
it is cheap, reproducible, and unit-testable.

Design contract:

* **Nothing is promoted.** Every survivor stays at evidence stage ``candidate``; this module
  only decides which candidates are worth an (expensive) look, never that anything is a bug.
* **Every drop is auditable.** A suppressed candidate keeps a machine-readable ``reason`` — we
  never silently discard scanner output, so a human can always audit what was filtered and why.
* **Conservative on real classes.** Hygiene/style rules and fixture/placeholder secrets are
  suppressed; genuine injection/authz/deserialization classes in real source are kept even at
  low confidence (better a human triages a weak real candidate than we hide it).

The funnel stages (see :class:`Reduction`): ``raw -> deduped -> product-path -> signal-rule ->
real-secret -> families -> survivors``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- rule families that are hygiene/style, never a bounty on their own -----------------------
# Suppressed regardless of path. Value is the human-facing reason. Real injection/authz/
# deserialization/SSRF classes are deliberately NOT here.
_LOW_VALUE_RULES: dict[str, str] = {
    # bandit style/hygiene
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

# --- weak single-engine heuristics: real classes, but a *single* scanner that cannot prove
# taint/verify is a weak signal. These survive only when a second independent engine agrees
# (corroboration) or confidence is high — otherwise they are suppressed (audited) so we do not
# spend AI validation on 62 un-tainted "string SQL" hits. On a real target a genuine SQLi is
# almost always ALSO caught by a taint engine (semgrep) or the LLM lane, which corroborates it.
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
_CORROBORATION_MIN = 2       # distinct engines at the same locus
_STRONG_CONF = 0.85          # a single engine this confident survives alone

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

# --- secrets: which rule ids / tools are "this is a secret" claims --------------------------
_SECRET_RULES = {"CWE-798"}
_SECRET_TOOLS = {"detect-secrets", "gitleaks"}

# files whose "secrets" are placeholders/fixtures by construction — a hit here is never a leak.
_PLACEHOLDER_FILE = re.compile(
    r"(\.example$|\.sample$|\.template$|\.dist$|"
    r"(^|/)\.env\.[^/]+$|"                       # .env.example / .env.local.example
    r"(^|/)docker-compose[^/]*\.ya?ml$|"
    r"(^|/)dockerfile[^/]*$|"
    r"\.(md|rst|txt)$)",
    re.IGNORECASE,
)

# --- path classification --------------------------------------------------------------------
_PATH_CLASSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("test", re.compile(r"(^|/)_*(tests?|specs?)_*(/|$)|(_test|\.test|\.spec)\.", re.I)),
    ("bench", re.compile(r"(^|/)bench(es|mark|marks|marking)?(/|$)", re.I)),
    # example/sample/fixture/mock/demo/submission as a substring of any path segment, so
    # `Example_Submissions/`, `example-app`, `sample_config` etc. are all caught.
    ("example", re.compile(r"(^|/)[^/]*(examples?|demos?|samples?|fixtures?|mocks?|"
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
_PATHCLASS_WEIGHT = {"source": 1.0, "config": 0.7, "deploy": 0.6}


def path_class(path: str) -> str:
    """Classify a file path into a coarse role. ``source`` is the default (real attack surface)."""
    p = str(path or "").replace("\\", "/").lstrip("./")
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
    # checkov packs "CKV_...: description" — keep just the id for grouping
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
    reason: str = ""              # suppression reason when kept is False
    corroborators: int = 1       # distinct tools flagging the same locus (>=1)
    score: float = 0.0
    raw: dict = field(default_factory=dict, repr=False, compare=False)  # original scanner row

    def public(self) -> dict:
        """Audit-friendly view (excludes the bulky raw row)."""
        return {"tool": self.tool, "rule": self.rule, "cwe": self.cwe, "path": self.path,
                "line": self.line, "severity": self.severity, "confidence": self.confidence,
                "summary": self.summary, "path_class": self.path_class, "kept": self.kept,
                "reason": self.reason, "corroborators": self.corroborators, "score": self.score}

    @property
    def locus(self) -> tuple[str, int]:
        return (self.path, self.line // 5)   # 5-line bucket for cross-tool corroboration

    @property
    def family_key(self) -> tuple[str, str]:
        return (self.cwe or self.rule, self.path_class)


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
        """Original scanner rows for the survivors — feed these downstream (validator/report)."""
        return [c.raw for c in self.survivors if c.raw]

    def summary(self) -> dict:
        return {"funnel": self.funnel, "survivors": len(self.survivors),
                "families": len(self.families),
                "top_families": [f.__dict__ for f in self.families[:12]]}

    def funnel_lines(self) -> list[str]:
        f = self.funnel
        order = ["raw", "deduped", "drop_non_product_path", "drop_low_value_rule",
                 "drop_weak_single_engine", "drop_placeholder_secret", "survivors", "families"]
        return [f"  {k:26} {f.get(k, 0)}" for k in order if k in f]


def _to_candidate(row: dict) -> Candidate:
    ja = row.get("json_answer") or {}
    try:
        line = int(ja.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    return Candidate(
        tool=_tool_of(row), rule=_rule_of(row), cwe=_cwe_of(row),
        path=str(ja.get("file_path") or "").replace("\\", "/").lstrip("./"),
        line=line, severity=str(row.get("severity") or "medium").lower(),
        confidence=float(row.get("confidence") or 0.0),
        summary=str(ja.get("summary") or ja.get("vulnerability_type") or ""),
        path_class="", raw=row)


def _suppression_reason(c: Candidate) -> str:
    """Return a reason to drop this candidate, or '' to keep it."""
    if c.path_class in _NONPRODUCT:
        return f"non-product-path:{c.path_class}"
    if c.rule in _LOW_VALUE_RULES:
        return f"low-value-rule:{c.rule} ({_LOW_VALUE_RULES[c.rule]})"
    for prefix, why in _LOW_VALUE_PREFIXES:
        if c.rule.startswith(prefix):
            return f"low-value-rule:{prefix}* ({why})"
    # secret claims: suppress placeholder files (.env.example, *.sample, compose/Dockerfile,
    # docs) and deploy manifests — those "secrets" are fixtures/defaults, not live leaks. A
    # real secret in genuine source/config survives for review.
    if c.cwe in _SECRET_RULES or c.tool in _SECRET_TOOLS:
        if _PLACEHOLDER_FILE.search(c.path) or c.path_class == "deploy":
            return "placeholder/deploy secret (not a live leak)"

    # weak single-engine heuristics survive only when corroborated or highly confident
    corroborated = c.corroborators >= _CORROBORATION_MIN
    strong = c.confidence >= _STRONG_CONF
    if not corroborated and not strong:
        if c.rule in _REQUIRES_CORROBORATION:
            return (f"weak-single-engine:{c.rule} "
                    f"({_REQUIRES_CORROBORATION[c.rule]}; needs corroboration)")
        # unverified detect-secrets entropy hit in source: needs a rule engine (gitleaks) or
        # a verified plugin to be worth AI time.
        if c.tool == "detect-secrets":
            return "weak-single-engine:detect-secrets-unverified (needs corroboration)"
        # high-FP tools (njsscan) survive only when corroborated or highly confident.
        if c.tool in _WEAK_TOOLS:
            return f"weak-single-engine:{c.tool} (high-FP tool; needs corroboration)"
    return ""


def _score(c: Candidate) -> float:
    base = _SEVERITY_WEIGHT.get(c.severity, 0.5) * (0.5 + 0.5 * min(1.0, max(0.0, c.confidence)))
    base *= _PATHCLASS_WEIGHT.get(c.path_class, 0.55)
    base += min(0.30, 0.15 * (c.corroborators - 1))     # cross-engine corroboration boost
    return round(base, 4)


def reduce_candidates(rows: list[dict]) -> Reduction:
    """Reduce raw scanner rows (flattened ``ToolBridge.findings``) to ranked hypothesis families.

    Accepts the canonical Aegis row shape produced by ``tool_registry._row`` (``json_answer``,
    ``severity``, ``confidence``, ``source``, ``scanner_metadata``).
    """
    raw = len(rows)
    cands = [_to_candidate(r) for r in rows]
    for c in cands:
        c.path_class = path_class(c.path)

    # 1) exact dedup (same tool+rule+path+line) — one scanner reporting the same locus twice
    seen: set[tuple] = set()
    deduped: list[Candidate] = []
    for c in cands:
        key = (c.tool, c.rule, c.path, c.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)

    # 2) cross-tool corroboration: distinct tools flagging the same file/line-bucket
    locus_tools: dict[tuple, set[str]] = {}
    for c in deduped:
        locus_tools.setdefault(c.locus, set()).add(c.tool)
    for c in deduped:
        c.corroborators = len(locus_tools.get(c.locus, {c.tool}))

    # 3) suppression (path -> rule -> secret-context), each with an audit reason
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

    # 4) family clustering (cwe-or-rule x path_class)
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

    # funnel: raw -> deduped -> survivors -> families, with an auditable breakdown of *why*
    # candidates were suppressed (every drop is categorized, nothing vanishes silently).
    cats: dict[str, int] = {}
    for c in suppressed:
        if c.reason.startswith("non-product"):
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
