"""Self-hint: let the model read the code and produce its own focused lead.

The single biggest yield lever in the DeepSeek-finds-RCE reports was a human "small hint"
that pointed the model at the suspicious area. This generates that lead automatically: a
cheap recon pass reads a broad sample of the repo and names the ONE place/pattern most
worth a deep look — a direction, not a finding. That lead then seeds the expensive
ensemble via operator_hint, focusing the whole budget the way a human hint would.

Deterministic-ish and cheap (one call over a bounded sample). Degrades to "no hint" on any
failure, so it never blocks the hunt. The lead is still just a prior — every hypothesis it
provokes is validated like any other.
"""

from __future__ import annotations

from pathlib import Path

_SRC_EXT = {".php", ".rb", ".py", ".js", ".ts", ".go", ".java", ".sol", ".rs"}
_NOISE = ("/test", "test/", "/vendor/", "node_modules", "/dist/", ".min.", "/spec/")

_SYSTEM = (
    "You are an elite application-security auditor doing rapid triage. Your job is to pick "
    "the ONE lead worth a deep review — you are not writing a report, you are pointing a "
    "teammate at the single weakest spot in this code.\n\n"
    "Method — follow untrusted input, not file order:\n"
    "1. Find where attacker-controlled data ENTERS: routes/controllers, AJAX/RPC/GraphQL "
    "handlers, webhooks, deserializers, request params ($_GET/$_POST/params[]/req.body), "
    "file/URL/SQL inputs, on-chain calldata.\n"
    "2. Find the dangerous EFFECTS near them: a DB query, shell/eval/exec, a file read/"
    "write/include, an auth/ownership/tenant decision, an outbound request, a fund transfer.\n"
    "3. The highest-yield lead is a SIBLING ASYMMETRY — one handler enforces a control "
    "(nonce, capability check, ownership/tenant check, signature, password) that a sibling "
    "reaching the SAME effect skips — or a sink fed directly by input with no guard between. "
    "Access-control/IDOR is the most common PAID bug: an object id or resource taken from "
    "the request and used without proving the caller owns it.\n\n"
    "Pick the single most promising and PAYABLE lead (access-control/IDOR, injection, SSRF, "
    "deserialization, unsafe file/command ops, auth bypass — cosmetic/DoS-only rarely pays). "
    "Name the EXACT file+function and the precise reason it is suspicious — specific enough "
    "that the deep pass can jump straight to it and test it. This is a DIRECTION, a "
    "hypothesis to verify — do NOT claim it is confirmed, and do not invent a lead if the "
    "sample looks clean (say so plainly). Return strict json: "
    '{"lead":"one specific sentence: where + the exact input + the missing guard","where":"path:function"}.'
)


def sample_sources(repo_root: str | Path, *, max_files: int = 10, per_file: int = 6000,
                   subpath: str = "") -> list[tuple[str, str]]:
    root = Path(repo_root) / subpath if subpath else Path(repo_root)
    if not root.is_dir():
        return []
    out: list[tuple[str, str]] = []
    for f in sorted(root.rglob("*")):
        if len(out) >= max_files:
            break
        if not (f.is_file() and f.suffix.lower() in _SRC_EXT):
            continue
        try:
            rel = str(f.relative_to(root))
        except Exception:
            continue
        # filter on the path RELATIVE to root (the full path may contain 'test' etc.)
        if any(n in ("/" + rel.lower().replace("\\", "/")) for n in _NOISE):
            continue
        out.append((rel, f.read_text(encoding="utf-8", errors="replace")[:per_file]))
    return out


def generate_hint(client, repository: str, sources: list[tuple[str, str]]) -> str:
    if not sources:
        return ""
    body = "\n\n".join(f"### FILE: {p}\n{c}" for p, c in sources)
    try:
        raw = client.complete_json([
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": f"Repository: {repository}\n\n{body[:100000]}"},
        ])
    except Exception:
        return ""
    lead = str((raw or {}).get("lead") or "").strip()
    where = str((raw or {}).get("where") or "").strip()
    if not lead:
        return ""
    return (f"{lead} (focus: {where})" if where and where.lower() not in lead.lower() else lead)[:600]


def auto_hint_for(repo_root: str | Path, repository: str, client, *, subpath: str = "") -> str:
    """Convenience: sample the repo and return a self-generated lead (or '')."""
    return generate_hint(client, repository, sample_sources(repo_root, subpath=subpath))
