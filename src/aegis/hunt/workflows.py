"""Research playbooks published into open·kritt — our corpus + detectors as workflows.

open·kritt scans code, and a workflow is its *what to look for*. These encode the
vulnerability classes we learned from the real bug-bounty report corpus
([[mdpsec-report-corpus]]) and built as Aegis detectors — access control (the
dominant class), server-side injection/SSRF, secrets & client-side, and the
smart-contract property checks — as focused, code-oriented hunts.

Each is a single terminal depth whose step emits the eight vulnerability keys
open·kritt records, so a hunt directly yields findings. Every prompt ends with a
falsification pass: report only what is proven reachable, never a guess — the same
"candidate is not verification" discipline the detectors follow.
"""

from __future__ import annotations

# The eight keys a terminal step must emit, with open·kritt's required types
# (line is numeric, trigger_flow is an array of steps, the rest are strings).
_VULN_OUTPUT = {
    "vulnerability_type": "string",
    "file_path": "string",
    "line": "number",
    "summary": "string",
    "explanation": "string",
    "trigger_flow": "array",
    "malicious_input_example": "string",
    "malicious_actor": "string",
}

_FALSIFY = (
    "\n\nEvidence standard: return one result per vulnerability you can prove is "
    "reachable from untrusted input in {{repo_full}}. For each, do a second-pass "
    "falsification — re-check the file path, line, the exact data flow, and any "
    "auth/validation guard on the path; if you cannot prove reachability, drop it. "
    "Populate all eight fields: vulnerability_type, file_path, line, summary, "
    "explanation (the vulnerable data flow), trigger_flow (attacker steps), "
    "malicious_input_example, malicious_actor. Names, comments, and tests are leads "
    "only — prove it from code. If nothing is provable, return no results."
)


def _spec(name, description, prompt):
    return {"name": name, "description": description, "prompt": prompt + _FALSIFY}


#: The playbooks, most-impactful class first (access control dominates the corpus).
WORKFLOWS = [
    _spec(
        "Aegis · Broken Access Control & IDOR",
        "Object-level and function-level authorization gaps: IDOR/BOLA, BFLA, missing "
        "auth, and cross-tenant access — the dominant bug-bounty class.",
        "You are a whitehat auditing {{repo_full}} for BROKEN ACCESS CONTROL. Map every "
        "route/handler/resolver and, for each, determine what authorization it enforces. "
        "Find:\n"
        "1. IDOR / BOLA — an object is fetched or mutated by an id/key taken from the "
        "request without an ownership or tenant check tying that object to the caller "
        "(e.g. findById(req.params.id) with no where-owner/tenant filter). Note "
        "sequential/guessable ids as mass-exposure.\n"
        "2. BFLA — privileged/admin actions (delete, role change, config, export, refund) "
        "reachable without a role/permission check.\n"
        "3. Missing authentication — state-changing or sensitive routes with no auth "
        "middleware where sibling routes have it.\n"
        "4. Cross-tenant — queries missing a tenant/org scope so one tenant reads "
        "another's data.\n"
        "Trace each from the route to the data access and confirm the guard is absent on "
        "that path.",
    ),
    _spec(
        "Aegis · Server-Side Injection & SSRF",
        "Untrusted input reaching a dangerous sink: SQL/NoSQL injection, command "
        "injection, SSRF, and path traversal.",
        "You are a whitehat auditing {{repo_full}} for SERVER-SIDE INJECTION. Trace "
        "untrusted input (request params/body/headers, external data) to dangerous "
        "sinks:\n"
        "1. SQL/NoSQL injection — input concatenated or interpolated into a query "
        "instead of a parameterized/prepared call.\n"
        "2. Command injection — input into exec/spawn/system/shell.\n"
        "3. SSRF — input controls the host/URL of an outbound request "
        "(fetch/axios/http/curl/webhook), enabling access to internal services or "
        "metadata endpoints.\n"
        "4. Path traversal — input into a filesystem path (read/write/send) without "
        "normalization/allowlist.\n"
        "Show the source→sink flow and confirm no sanitizer or allowlist neutralizes it.",
    ),
    _spec(
        "Aegis · Secrets & Client-Side",
        "Hardcoded secrets and client-side trust issues: exposed credentials, unsafe "
        "postMessage/origin, and DOM XSS sinks.",
        "You are a whitehat auditing {{repo_full}} for secrets and client-side trust "
        "flaws. Find:\n"
        "1. Hardcoded secrets — API keys, tokens, passwords, private keys, or cloud "
        "credentials committed in source or client-delivered bundles (distinguish live "
        "credentials from obvious test/dummy values).\n"
        "2. Unsafe cross-window messaging — postMessage without a targetOrigin, or "
        "message handlers that act on data without validating event.origin against an "
        "anchored allowlist.\n"
        "3. DOM XSS — untrusted input reaching innerHTML / outerHTML / "
        "dangerouslySetInnerHTML / document.write / eval without encoding.\n"
        "For each, show where the secret lives or the untrusted value flows to the sink.",
    ),
    _spec(
        "Aegis · Systems, Memory Safety & Crypto",
        "For systems code (Go, C/C++, Rust): memory-safety, integer, concurrency, "
        "untrusted-input parsing, resource-exhaustion, and cryptographic-misuse bugs.",
        "You are a whitehat auditing the systems code in {{repo_full}} (Go, C/C++, Rust, "
        "and similar). Find:\n"
        "1. Memory safety — buffer/stack/heap overflows, out-of-bounds read/write, "
        "use-after-free, double-free, null/nil dereference, uninitialized memory; "
        "misuse of `unsafe`, cgo, raw pointers, or manual length/index math on "
        "attacker-influenced data.\n"
        "2. Integer bugs — overflow/underflow or signedness errors that feed a length, "
        "index, allocation size, or security decision.\n"
        "3. Concurrency — data races or TOCTOU on security-relevant state.\n"
        "4. Untrusted-input parsing — packet/protocol/file decoders that trust "
        "length/offset fields, enabling OOB or panic on malformed input.\n"
        "5. Resource exhaustion / DoS — unbounded allocation, decompression bombs, or "
        "panics reachable from remote input.\n"
        "6. Cryptographic misuse — weak algorithms (MD5/SHA1/DES/RC4/ECB), insecure or "
        "predictable randomness for security, hardcoded keys/IVs, nonce/IV reuse, "
        "missing or incorrect signature/MAC verification, disabled certificate/hostname "
        "validation (e.g. InsecureSkipVerify), and non-constant-time comparison of "
        "secrets.\n"
        "Prefer bugs reachable from remote or attacker-controlled input.",
    ),
    _spec(
        "Aegis · Web Security Misconfiguration",
        "Transport/response and API misconfigurations: CORS, CSP, security headers, "
        "cookie flags, open redirect, CSRF, cacheable secrets, GraphQL exposure.",
        "You are a whitehat auditing {{repo_full}} for web security misconfigurations. "
        "Find:\n"
        "1. CORS — a credentialed response that reflects an arbitrary Origin, or "
        "Access-Control-Allow-Origin '*' with credentials.\n"
        "2. CSP — missing, or weakened by unsafe-inline / unsafe-eval on a page that "
        "renders untrusted content.\n"
        "3. Missing security headers — no X-Content-Type-Options nosniff, no frame "
        "protection (X-Frame-Options / frame-ancestors) enabling clickjacking, no HSTS.\n"
        "4. Cookie flags — session/auth cookies set without HttpOnly, Secure, or "
        "SameSite.\n"
        "5. Open redirect — a redirect target taken from user input without an "
        "allowlist.\n"
        "6. CSRF — state-changing endpoints with no CSRF token / SameSite protection.\n"
        "7. Cacheable sensitive responses — authenticated/PII responses returned "
        "cacheable.\n"
        "8. GraphQL — introspection enabled in production, missing field-level "
        "authorization, or no query depth/complexity limit.\n"
        "Point to the config/handler/middleware where the setting is made (or missing).",
    ),
    _spec(
        "Aegis · Smart Contract (Solidity)",
        "On-chain value-drain vectors for Solidity repos: reentrancy, missing access "
        "control, unsafe arithmetic, unchecked calls, tx.origin, unguarded destruct.",
        "You are a whitehat auditing the Solidity in {{repo_full}} for value-draining "
        "vulnerabilities. Find:\n"
        "1. Reentrancy — an external call (call{value}, transfer, token.transfer) made "
        "before internal balances/state are settled (violating checks-effects-"
        "interactions).\n"
        "2. Missing access control — mint/withdraw/ownership/upgrade/selfdestruct or a "
        "transfer to an arbitrary recipient reachable without an owner/role guard (a "
        "withdraw of the caller's own funds to msg.sender is self-scoped, not a bug).\n"
        "3. Unsafe arithmetic — value math that can overflow/underflow (pre-0.8 without "
        "SafeMath, or inside unchecked{}).\n"
        "4. Unchecked external call return; tx.origin used for authorization; "
        "selfdestruct/delegatecall without access control.\n"
        "Only report if it is reachable by an external caller and moves or locks value.",
    ),
]


def build_workflow(spec: dict) -> dict:
    """Turn a spec into an open·kritt POST /api/workflows body (single terminal depth)."""
    return {
        "name": spec["name"],
        "description": spec["description"],
        "levels": [{
            "depth": 0,
            "multiOutput": True,             # emit one result per finding
            "consumesAll": False,
            "outputFormat": dict(_VULN_OUTPUT),
            "steps": [{"name": spec["name"][:60], "content": spec["prompt"]}],
        }],
    }


def publish_workflows(client, specs=WORKFLOWS) -> dict:
    """Create each workflow that doesn't already exist (idempotent by name)."""
    existing = {str(w.get("name")) for w in client.list_workflows()}
    created, skipped = [], []
    for spec in specs:
        if spec["name"] in existing:
            skipped.append(spec["name"])
            continue
        resp = client.create_workflow(build_workflow(spec))
        created.append({"id": resp.get("id"), "name": spec["name"]})
    return {"created": created, "skipped": skipped}
