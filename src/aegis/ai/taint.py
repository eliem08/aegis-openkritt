"""Lightweight source→sink taint hints to feed the generator reachability leads.

Not a real dataflow engine — a pragmatic, language-agnostic heuristic slicer. It finds
where untrusted input enters (sources) and where dangerous operations happen (sinks) in
a file, tracks the variables that carry a source, and emits candidate flows a source
variable reaches a sink. These are LEADS, injected into the generator prompt so the
model traces a real path instead of guessing — the session's misses were mostly the
model not connecting source to sink.

Original heuristics. Deterministic. It never claims a flow is proven — only "worth
tracing", and the generator + validator still have to prove it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Untrusted-input sources across common stacks (request data, handler params, on-chain).
_SOURCES = re.compile(
    r"req\.(?:params|query|body|headers|cookies)\b|request\.(?:GET|POST|args|form|json|data|headers)\b"
    r"|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b|params\[|ctx\.request|event\.(?:body|queryStringParameters)"
    r"|getParameter\(|@RequestParam|@PathVariable|msg\.(?:sender|data|value)\b|calldata\b"
    r"|process\.argv|os\.Args\b|r\.URL\.Query\(\)|c\.(?:Query|Param|PostForm)\(",
    re.IGNORECASE)

# Dangerous sinks, tagged with the weakness class they suggest.
_SINKS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"(?:\.|->)(?:query|execute|raw|prepare)\s*\(|(?:mysqli_|pg_|sqlite_)?query\s*\("
                r"|db\.Raw\(|createQueryBuilder\(", re.I),
     "sql/query injection"),
    (re.compile(r"\b(?:exec|execSync|spawn|system|popen|subprocess|Runtime\.getRuntime|os/exec)\b", re.I),
     "command injection"),
    (re.compile(r"\b(?:fetch|axios|http\.get|http\.request|urllib|HttpClient|requests\.(?:get|post))\b", re.I),
     "SSRF / outbound request"),
    (re.compile(r"innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write|\beval\b|new Function\(", re.I),
     "DOM XSS / code exec"),
    (re.compile(r"readFile|writeFile|open\s*\(|os\.Open|ioutil\.ReadFile|sendFile|include\s*\(|require\s*\(", re.I),
     "path traversal / file access"),
    (re.compile(r"\.call\{|delegatecall|selfdestruct|transfer\(|_mint\(|_burn\(", re.I),
     "unsafe contract call / value flow"),
    (re.compile(r"findById|findOne|\.get\s*\(|WHERE\s+id\s*=|\.deleteOne|\.updateOne", re.I),
     "object lookup (IDOR if unscoped)"),
)

_ASSIGN = re.compile(r"(?:const|let|var|final|\w[\w<>\[\]]*)?\s*(\$?[A-Za-z_]\w*)\s*[:=]\s*(.+)")
_IDENT = re.compile(r"\$?[A-Za-z_]\w*")


@dataclass(frozen=True)
class TaintFlow:
    source_line: int
    source_snippet: str
    sink_line: int
    sink_snippet: str
    sink_class: str
    carrier: str            # the variable that carries the taint


def _tainted_vars(lines: list[str]) -> dict[str, int]:
    """Variables assigned (directly) from a source, with the line they were tainted on."""
    tainted: dict[str, int] = {}
    for i, line in enumerate(lines, start=1):
        if not _SOURCES.search(line):
            continue
        m = _ASSIGN.match(line.strip())
        if m:
            tainted[m.group(1)] = i
        else:                                    # inline source use (no assignment) — mark line
            tainted.setdefault(f"@line{i}", i)
    # one propagation hop: y = f(x) where x is tainted -> y tainted
    for i, line in enumerate(lines, start=1):
        m = _ASSIGN.match(line.strip())
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        if lhs in tainted:
            continue
        if any(v in set(_IDENT.findall(rhs)) for v in tainted if not v.startswith("@line")):
            tainted[lhs] = tainted.get(lhs, i)
    return tainted


def extract_flows(content: str, *, max_flows: int = 12) -> list[TaintFlow]:
    """Candidate source→sink flows in a file: a tainted variable (or an inline source on
    the same line) appearing at a sink. Deterministic; leads, not proofs."""
    lines = content.splitlines()
    tainted = _tainted_vars(lines)
    var_names = {v for v in tainted if not v.startswith("@line")}
    flows: list[TaintFlow] = []
    for i, line in enumerate(lines, start=1):
        for pattern, klass in _SINKS:
            if not pattern.search(line):
                continue
            idents = set(_IDENT.findall(line))
            own_lhs = m.group(1) if (m := _ASSIGN.match(line.strip())) else None
            # candidate carriers: tainted vars used on this line, excluding the var being
            # assigned here; pick the earliest-tainted (the real source) deterministically
            candidates = [v for v in var_names if v in idents and v != own_lhs]
            carrier = min(candidates, key=lambda v: (tainted[v], v)) if candidates else None
            inline_source = _SOURCES.search(line) is not None
            if carrier is None and not inline_source:
                continue
            src_line = tainted.get(carrier, i) if carrier else i
            flows.append(TaintFlow(
                source_line=src_line, source_snippet=lines[src_line - 1].strip()[:160],
                sink_line=i, sink_snippet=line.strip()[:160], sink_class=klass,
                carrier=carrier or "(inline)"))
            break                                 # one flow per sink line
        if len(flows) >= max_flows:
            break
    return flows


def taint_hints_text(flows: list[TaintFlow]) -> str:
    """A prompt block of the candidate flows for the generator to trace and prove."""
    if not flows:
        return ""
    lines = [
        "\n## Taint leads (heuristic — trace and PROVE or discard each)",
        "Untrusted input may reach a dangerous sink along these paths. For each, confirm "
        "the real data flow and whether a guard neutralizes it; report only the ones you "
        "can prove reachable. These are leads, not findings.",
    ]
    for f in flows:
        lines.append(
            f"- L{f.source_line} source `{f.source_snippet}` → L{f.sink_line} "
            f"{f.sink_class} `{f.sink_snippet}` (carrier: {f.carrier})")
    return "\n".join(lines)
