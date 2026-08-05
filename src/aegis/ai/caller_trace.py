"""Caller-tracing: pull the code that CALLS a flagged function into the review context.

The mainwp run exposed the gap: a helper like `save($path)` writes user content to $path
but comments "verify in caller" — it defers the auth/sanitization check upstream. Analysing
the helper alone can't decide if it's exploitable; you must read its CALLERS and see whether
each one supplies the guard the helper omits. `_context` follows imports (what a file USES),
never callers (who USES it). This adds the missing direction.

Given a finding at file:line, it finds the enclosing function, scans the repo for call sites
of that function, and returns the CALLER functions' code as extra slices — so the validator
can confirm-or-refute a deferred-verification pattern instead of guessing.

Heuristic and bounded (like reachability). Pure text analysis, no execution.
"""

from __future__ import annotations

from pathlib import Path

from .reachability import _SRC_EXT, enclosing_function

_MAX_SPAN = 80          # cap how many lines of a caller function we capture


def _function_end(lines: list[str], start_idx: int) -> int:
    """End line index (exclusive) of the function whose def is at start_idx. Brace-matched
    for C-like/PHP/JS/Go; indentation-based for Python/Ruby; always bounded by _MAX_SPAN."""
    hard = min(len(lines), start_idx + _MAX_SPAN)
    # brace languages: capture until the brace opened by the def closes
    joined = "\n".join(lines[start_idx:hard])
    if "{" in joined:
        depth, seen = 0, False
        for i in range(start_idx, hard):
            for ch in lines[i]:
                if ch == "{":
                    depth += 1; seen = True
                elif ch == "}":
                    depth -= 1
            if seen and depth <= 0:
                return i + 1
        return hard
    # indentation languages: end at the next line dedented to <= the def's indent
    def_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
    for i in range(start_idx + 1, hard):
        ln = lines[i]
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= def_indent:
            return i
    return hard


#: never trace callers through these — minified/vendored/generated client-side noise where
#: a common name like save()/update()/get() collides with unrelated library methods.
_NOISE = ("/assets/", "/asset/", "/vendor/", "/dist/", "/build/", "/static/", "node_modules",
          ".min.", ".bundle.", "bower_components", "jquery", "bootstrap", "datatables")


def find_callers(repo_root: str | Path, func_name: str, *, lang_ext: str = "",
                 self_file: str = "", max_callers: int = 4) -> list[dict]:
    """Call sites of ``func_name``, each with the enclosing CALLER function's code. Skips the
    definition itself. When ``lang_ext`` is given, only files with that extension are scanned
    (a PHP finding must not match a JS .save() call). Returns [{file, line, caller, snippet}]."""
    import re

    root = Path(repo_root)
    if not func_name or not root.is_dir():
        return []
    # a call: name followed by '(' (or '::name('/'->name('), not a definition
    call_re = re.compile(r"(?<![\w$])" + re.escape(func_name) + r"\s*\(")
    def_re = re.compile(r"\b(function|def|func)\s+" + re.escape(func_name) + r"\b")
    exts = {lang_ext.lower()} if lang_ext else _SRC_EXT
    out: list[dict] = []
    for f in sorted(root.rglob("*")):
        if len(out) >= max_callers:
            break
        if not (f.is_file() and f.suffix.lower() in exts):
            continue
        if any(n in ("/" + f.as_posix().lower()) for n in _NOISE):
            continue                                 # skip minified/vendored library noise
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if func_name not in text:
            continue
        lines = text.splitlines()
        for j, ln in enumerate(lines):
            if len(out) >= max_callers:
                break
            if def_re.search(ln) or not call_re.search(ln):
                continue
            enc = enclosing_function(lines, j + 1)      # who is doing the calling
            if enc is None:
                start = max(0, j - 3); snippet_lines = lines[start:j + 6]
                caller_name = "(top-level)"
            else:
                caller_name, _params, def_line = enc
                if caller_name == func_name:
                    continue                            # a recursive call inside the def
                start = def_line - 1
                snippet_lines = lines[start:_function_end(lines, start)]
            rel = f.relative_to(root).as_posix()
            out.append({"file": rel, "line": j + 1, "caller": caller_name,
                        "snippet": "\n".join(snippet_lines)[:4000]})
    return out


def caller_slices(repo_root: str | Path, relative: str, line: int, *, max_callers: int = 4):
    """For a finding at relative:line, return SourceSlices of the functions that CALL its
    enclosing function — the code that must (or must not) supply the deferred guard."""
    from .agents.contracts import SourceSlice

    root = Path(repo_root)
    fpath = root / relative
    if not fpath.is_file():
        hits = list(root.rglob(Path(relative).name))
        if not hits:
            return []
        fpath = hits[0]
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    enc = enclosing_function(lines, int(line or 1))
    if enc is None:
        return []
    func_name = enc[0]
    slices = []
    lang_ext = fpath.suffix.lower()                  # trace only same-language callers
    for c in find_callers(root, func_name, lang_ext=lang_ext, self_file=str(fpath),
                          max_callers=max_callers):
        header = (f"// CALLER of {func_name}() — {c['file']}:{c['line']} in {c['caller']}(). "
                  f"Does this caller supply the guard {func_name}() omits?\n")
        slices.append(SourceSlice(path=f"caller::{c['file']}", content=header + c["snippet"]))
    return slices
