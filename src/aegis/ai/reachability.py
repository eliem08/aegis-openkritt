"""Lightweight reachability heuristic: is the flagged sink actually callable?

Motivated by a real miss — an "XSS via render inline" candidate whose vulnerable method
`render_logout_error(logout_request)` was invoked with ZERO args (arity mismatch), so it
raised before the sink ran: dead on that path. A taint→sink finding is worthless if no
call site can reach the sink.

This is a HEURISTIC advisory, not a compiler. Given the finding's file+line, it finds the
enclosing function, then scans the repo for call sites and compares argument counts. It
emits a note (callers found, arity match) and a verdict: "reachable", "no-callers", or
"arity-mismatch". The validator consumes the note; it is never a silent auto-reject on its
own, because heuristic call-graphs miss dynamic dispatch, DI, routing, and reflection.
"""

from __future__ import annotations

import re
from pathlib import Path

# def forms across the languages the hunt sees. Group 1 = name, group 2 = param list.
_DEF_PATTERNS = [
    re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"),            # python/ruby with parens
    re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*$"),                       # ruby no-paren (0 params)
    re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"),  # js/php
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)"),   # go
    re.compile(r"^\s*function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"),        # solidity
    re.compile(r"^\s*(?:public|private|protected|static|\s)*[A-Za-z_<>\[\]]+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{"),  # java/c-like
]
_SRC_EXT = {".py", ".rb", ".js", ".ts", ".php", ".go", ".sol", ".java", ".c", ".cpp", ".cs"}


def _param_count(params: str) -> int:
    p = params.strip()
    if not p:
        return 0
    # drop defaults/self, count top-level commas
    parts = [x.strip() for x in _split_top(p) if x.strip()]
    parts = [x for x in parts if x not in ("self", "cls")]
    return len(parts)


def _split_top(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def enclosing_function(lines: list[str], line: int) -> tuple[str, int, int] | None:
    """Scan upward from a 1-based line for the def that encloses it.
    Returns (name, required_param_count, def_line) or None."""
    for i in range(min(line, len(lines)) - 1, -1, -1):
        for pat in _DEF_PATTERNS:
            m = pat.match(lines[i])
            if m:
                name = m.group(1)
                params = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                return name, _param_count(params), i + 1
    return None


def _args_after(name: str, line: str) -> int:
    """Argument count of a call to ``name`` on ``line``. Handles paren calls and Ruby
    paren-less calls. Returns -1 only when genuinely ambiguous."""
    idx = line.find(name)
    if idx < 0:
        return -1
    rest = line[idx + len(name):].split("#")[0].rstrip()
    if rest.startswith("("):
        end = rest.find(")")
        inner = (rest[1:end] if end >= 0 else rest[1:]).strip()
        return 0 if not inner else len([x for x in _split_top(inner) if x.strip()])
    rest = rest.strip()
    # bare method name with nothing (or a block / chain / operator) after it -> 0 positional args
    if rest == "" or rest[:1] in ".{&|?=" or rest.startswith("do"):
        return 0
    return -1                           # paren-less call WITH args -> don't guess, stay lenient


# names that are entry points (called by framework/routing/reflection, not by a local caller)
_ENTRYPOINT = re.compile(r"^(main|handler|handle|index|create|update|destroy|show|new|run|"
                         r"get|post|put|delete|patch|call|invoke|test_|setup|teardown)", re.IGNORECASE)


def check(repo_root: str | Path, rel_file: str, line: int) -> dict:
    """Reachability note for a finding at repo_root/rel_file:line."""
    root = Path(repo_root)
    fpath = root / rel_file
    if not fpath.is_file():
        # try to locate by basename
        hits = list(root.rglob(Path(rel_file).name))
        if not hits:
            return {"verdict": "unknown", "note": "source file not found"}
        fpath = hits[0]
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return {"verdict": "unknown", "note": "unreadable"}
    fn = enclosing_function(lines, line)
    if not fn:
        return {"verdict": "unknown", "note": "no enclosing function"}
    name, params, def_line = fn
    if _ENTRYPOINT.match(name):
        return {"verdict": "reachable", "function": name,
                "note": f"{name} looks like a framework entry point"}
    # scan the repo for call sites (name followed by '(' or bare in ruby)
    callers, arities = [], []
    call_re = re.compile(r"(?<![\w.])" + re.escape(name) + r"\s*(\(|$|\s)")
    for f in root.rglob("*"):
        if not (f.is_file() and f.suffix.lower() in _SRC_EXT):
            continue
        try:
            txt = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for j, ln in enumerate(txt.splitlines(), 1):
            if f == fpath and j == def_line:
                continue                # skip the definition itself
            if re.search(r"\bdef\s+" + re.escape(name) + r"\b", ln) or \
               re.search(r"\bfunction\s+" + re.escape(name) + r"\b", ln):
                continue                # skip other definitions/overrides
            if call_re.search(ln):
                callers.append(f"{f.relative_to(root)}:{j}")
                arities.append(_args_after(name, ln))
    if not callers:
        return {"verdict": "no-callers", "function": name, "params": params,
                "note": f"{name} has no call site in the repo (possibly dead/unreachable)"}
    # arity: if every caller that we could parse passes a different count than required
    parsed = [a for a in arities if a >= 0]
    if params > 0 and parsed and all(a != params for a in parsed):
        return {"verdict": "arity-mismatch", "function": name, "params": params,
                "callers": callers[:5], "arg_counts": parsed[:5],
                "note": f"{name} needs {params} arg(s); all {len(parsed)} call site(s) pass "
                        f"{sorted(set(parsed))} — unreachable as written"}
    return {"verdict": "reachable", "function": name, "callers": callers[:5]}
