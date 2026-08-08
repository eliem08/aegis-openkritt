"""Deterministic candidate-reduction funnel.

The funnel suppresses scanner noise before expensive reasoning but never promotes a scanner hit
into a vulnerability. Suppression is intentionally conservative around credentials: deployment
and CI/IaC files are real attack surface, so credible secrets there survive unless the *filename*
clearly marks the content as an example/template/fixture.
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
}
_CORROBORATION_MIN = 2
_STRONG_CONF = 0.85

_LOW_VALUE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("CKV_DOCKER_", "container image hygiene (HEALTHCHECK/USER/tag), not a vuln"),
)

_SECRET_RULES = {"CWE-798"}
_SECRET_TOOLS = {"detect-secrets", "gitleaks"}

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
    ("example", re.compile(r"(^|/)(examples?|demos?|samples?|fixtures?|mocks?)(/|$)", re.I)),
    ("vendor", re.compile(r"(^|/)(vendor|third_party|node_modules|bower_components)(/|$)", re.I)),
    ("generated", re.compile(r"[.-]min\.(js|css)$|\.bundle\.js$|(^|/)(dist|build)(/|$)|"
                             r"_generated|_pb2|\.pb\.", re.I)),
    ("docs", re.compile(r"(^|/)docs?(/|$)|\.(md|rst)$|(^|/)readme", re.I)),
    ("deploy", re.compile(r"(^|/)(deploy|\.github|k8s|helm|charts?|terraform)(/|$)|"
                          r"(^|/)docker-compose[^/]*\.ya?ml$|(^|/)dockerfile[^/]*$|\.tf$", re.I)),
    ("config", re.compile(r"\.(ya?ml|toml|ini|cfg|conf|json|env)$|(^|/)\.env", re.I)),
)

_NONPRODUCT = {"test", "bench", "example", "vendor", "generated", "docs"}
_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.15}
_PATHCLASS_WEIGHT = {"source": 1.0, "config": 0.8, "deploy": 0.8}


def _normalize_path(path: str) -> str:
    """Normalize separators without destroying meaningful leading dot-directories.

    ``str.lstrip('./')`` removed the dot from paths such as ``.github/workflows`` and
    ``.env``, causing CI/IaC and configuration files to be misclassified. Only literal
    relative-path prefixes are removed here.
    """
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
        order = ["raw", "deduped", "drop_non_product_path", "drop_low_value_rule",
                 "drop_weak_single_engine", "drop_placeholder_secret", "survivors", "families"]
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


def _suppression_reason(c: Candidate) -> str:
    if c.path_class in _NONPRODUCT:
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
                    f"({_REQUIRES_CORROBORATION[c.rule]}; needs corroboration)")
        if c.tool == "detect-secrets":
            return "weak-single-engine:detect-secrets-unverified (needs corroboration)"
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

    locus_tools: dict[tuple, set[str]] = {}
    for c in deduped:
        locus_tools.setdefault(c.locus, set()).add(c.tool)
    for c in deduped:
        c.corroborators = len(locus_tools.get(c.locus, {c.tool}))

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
