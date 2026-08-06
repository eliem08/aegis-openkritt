"""AI-driven hardcoded-secret hunting in JavaScript — the P1-leak lane.

The reliable bounty shape: a *live secret* credential shipped inside a first-party JS
bundle. The hard part is not finding key-shaped strings (regex does that) — it is telling
a real exploitable secret (AWS secret key, Stripe sk_live, private key) from the 90% that
are *supposed* to be public (Stripe pk_live, Google Maps/Firebase browser keys, public
client IDs). That discrimination is what turns a P1 into a dupe/N-A, and it is exactly
where a strong LLM triage earns its place.

Pipeline: deterministic high-signal extraction over supplied JS -> DeepSeek triage of each
unique candidate (secret vs public, key type, what it grants, severity, exploitability,
confidence) -> ranked findings. Raw values are REDACTED throughout.

BOUNDARY (see [[live-attack-boundary]]): this is analytical only. It operates on JS the
operator has ALREADY acquired within authorized scope (a local dir/files); it does not
fetch live third-party hosts on its own, and it NEVER uses a discovered key against any
service — classification is static, from format + context. Confirming a key is live is a
human step, done safely and within scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

# High-signal secret patterns. is_public=True marks families that are DESIGNED to ship in
# client code (browser keys, publishable keys) — real findings are the is_public=False set,
# but we surface public matches too so the triage can down-rank them explicitly.
@dataclass(frozen=True)
class _Pat:
    name: str
    regex: re.Pattern
    is_public: bool = False


_PATTERNS: tuple[_Pat, ...] = (
    _Pat("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _Pat("aws-secret-access-key", re.compile(r"(?i)aws.{0,20}?(?:secret|sk).{0,5}?['\"=: ]([A-Za-z0-9/+]{40})\b")),
    _Pat("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), is_public=True),
    _Pat("stripe-secret-key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    _Pat("stripe-publishable-key", re.compile(r"\bpk_live_[0-9a-zA-Z]{20,}\b"), is_public=True),
    _Pat("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    _Pat("gitlab-pat", re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b")),
    _Pat("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    _Pat("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}")),
    _Pat("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    _Pat("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    _Pat("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    _Pat("twilio-api-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    _Pat("twilio-account-sid", re.compile(r"\bAC[0-9a-f]{32}\b"), is_public=True),
    _Pat("mailgun-key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    _Pat("npm-token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    _Pat("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    _Pat("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    _Pat("firebase-db-url", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), is_public=True),
    _Pat("bearer-token", re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}")),
    _Pat("generic-secret-assign", re.compile(
        r"(?i)(?:api[_-]?key|secret|passwd|password|token|access[_-]?key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]")),
)

_MIN_CONTEXT, _MAX_CONTEXT = 40, 200


def _redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 10:
        return v[:2] + "..."
    return f"{v[:4]}...{v[-4:]} (len {len(v)})"


@dataclass
class Candidate:
    kind: str                 # pattern name
    line: int
    redacted: str             # never the raw value
    context: str              # redacted surrounding text
    is_public_pattern: bool
    source: str = ""          # file or url the JS came from
    _raw_head: str = ""       # first 6 chars (prefix) for triage — NOT the full secret


def extract_candidates(js_text: str, *, source: str = "") -> list[Candidate]:
    """Deterministic high-signal extraction. Returns redacted candidates (no raw values)."""
    out: list[Candidate] = []
    seen: set[tuple[str, int]] = set()
    lines = (js_text or "").splitlines()
    for i, line in enumerate(lines, start=1):
        for pat in _PATTERNS:
            for m in pat.regex.finditer(line):
                raw = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
                key = (pat.name, i)
                if key in seen:
                    continue
                seen.add(key)
                ctx = line.strip()
                ctx = ctx[:_MAX_CONTEXT]
                # redact the raw value inside the context snippet
                ctx_red = ctx.replace(raw, _redact(raw)) if raw in ctx else ctx
                out.append(Candidate(
                    kind=pat.name, line=i, redacted=_redact(raw), context=ctx_red[:_MAX_CONTEXT],
                    is_public_pattern=pat.is_public, source=source, _raw_head=raw[:6]))
    return out


class SecretTriage(BaseModel):
    """The LLM's verdict on one candidate — the discrimination that makes this valuable."""
    model_config = ConfigDict(extra="ignore")

    verdict: str = Field(description="secret | public | test-or-placeholder | unknown")
    key_type: str = ""
    grants: str = Field(default="", description="what an attacker gains if it is live")
    severity: str = "medium"          # critical | high | medium | low | info
    exploitability: str = ""          # how it would be abused, in scope
    likely_live: float = 0.0          # 0..1 heuristic that this is a real active credential
    confidence: float = 0.0
    reason: str = ""
    is_public_client_key: bool = False   # true = intended to be in client code (down-rank)


@dataclass
class SecretFinding:
    kind: str
    source: str
    line: int
    redacted: str
    triage: SecretTriage
    score: float = 0.0

    def as_dict(self) -> dict:
        t = self.triage
        return {"kind": self.kind, "source": self.source, "line": self.line,
                "redacted": self.redacted, "verdict": t.verdict, "key_type": t.key_type,
                "severity": t.severity, "grants": t.grants, "exploitability": t.exploitability,
                "likely_live": t.likely_live, "confidence": t.confidence,
                "is_public_client_key": t.is_public_client_key, "reason": t.reason,
                "score": round(self.score, 3)}


_SEV_W = {"critical": 5.0, "high": 3.5, "medium": 2.0, "low": 1.0, "info": 0.3}


_TRIAGE_SYSTEM = """\
You are an elite bug-bounty secrets analyst triaging a candidate credential found in a
first-party JavaScript bundle. Your ONE job: decide whether this is a REAL, exploitable
secret (a P1/P2 bounty) or a value that is SUPPOSED to ship in client code (worthless to
report). Getting this right is the whole game — reporting a public key burns the hunter's
reputation; missing a live secret leaves money on the table.

You are given the key TYPE, a REDACTED value (prefix + length only — you will not see the
full secret), and the surrounding code line. Reason from format, prefix, and context.

KNOW THE TAXONOMY — public (client-safe) vs secret (must never ship):
- SECRET (report if live): AWS secret access key (40-char), AWS access key id AKIA*,
  Stripe sk_live_/rk_live_, GitHub ghp_/gho_/ghs_, GitLab glpat-, Slack xoxb/xoxp/xoxs,
  Slack webhook URL, private keys (-----BEGIN PRIVATE KEY-----), SendGrid SG.*, Twilio
  API key SK*, Mailgun key-*, npm_*, OpenAI sk-*, Anthropic sk-ant-*, DB connection
  strings with credentials, session/JWT with real claims and a live signature.
- PUBLIC by design (do NOT report as a leak): Stripe pk_live_/pk_test_ (publishable),
  Google/Firebase browser API keys AIza* used for Maps/Firebase (restricted by referrer;
  only report if unrestricted AND grants sensitive API access), Twilio Account SID AC*
  (an identifier, not a secret), Firebase config (apiKey/authDomain/projectId is public),
  OAuth *client_id*, Sentry public DSN, analytics/measurement IDs, reCAPTCHA site keys.
- TEST/PLACEHOLDER: values containing test, example, xxxx, 000000, changeme, your_key,
  <...>, sk_test_, or obvious dummies -> verdict "test-or-placeholder".

RULES:
- A Google AIza* key is usually a browser key -> is_public_client_key=true UNLESS context
  shows it guards a sensitive backend API; then severity high only if plausibly unrestricted.
- Stripe: pk_* is PUBLIC (is_public_client_key=true); sk_*/rk_* is SECRET, severity high.
- Never claim a value is live — you cannot test it. Estimate likely_live from realism of
  format + context (a hardcoded prod-looking sk_live_ near an API call is high; a value in
  a *.test.js or a comment is low).
- Prefer precision. When genuinely unsure, verdict "unknown" with modest confidence.

Return ONLY this JSON object, no prose:
{"verdict":"secret|public|test-or-placeholder|unknown","key_type":"","grants":"what an
attacker gains if live","severity":"critical|high|medium|low|info","exploitability":"how
it is abused, briefly","likely_live":0.0,"confidence":0.0,"reason":"one sentence",
"is_public_client_key":false}"""


def triage_candidate(client, cand: Candidate) -> SecretTriage:
    """Ask DeepSeek to classify one candidate. Only redacted data leaves the process."""
    user = (
        f"Candidate secret in first-party JS.\n"
        f"- key type (regex family): {cand.kind}\n"
        f"- pattern is client-public by default: {cand.is_public_pattern}\n"
        f"- redacted value: {cand.redacted}\n"
        f"- value prefix: {cand._raw_head!r}\n"
        f"- source: {cand.source or 'n/a'} (line {cand.line})\n"
        f"- code context: {cand.context}\n\n"
        "Triage it. Return the JSON object only.")
    try:
        data = client.complete_json([
            {"role": "system", "content": _TRIAGE_SYSTEM},
            {"role": "user", "content": user},
        ])
        return SecretTriage.model_validate(data)
    except Exception as exc:
        return SecretTriage(verdict="unknown", confidence=0.0,
                            reason=f"triage error: {type(exc).__name__}",
                            is_public_client_key=cand.is_public_pattern)


def _score(cand: Candidate, t: SecretTriage) -> float:
    if t.verdict in ("public", "test-or-placeholder") or t.is_public_client_key:
        base = 0.2
    elif t.verdict == "secret":
        base = _SEV_W.get(t.severity, 2.0)
    else:
        base = 1.0
    return round(base * (0.4 + 0.6 * t.confidence) * (0.5 + 0.5 * t.likely_live), 3)


def hunt_js_secrets(js_sources: dict[str, str], client, *, max_candidates: int = 60) -> list[SecretFinding]:
    """Extract + triage secrets across supplied JS. ``js_sources`` maps source-name -> JS text.
    Only redacted data is sent to the model. Returns findings ranked most-serious first."""
    cands: list[Candidate] = []
    for name, text in js_sources.items():
        cands.extend(extract_candidates(text, source=name))
    # de-dup identical (kind, redacted, source) and cap cost
    uniq, seen = [], set()
    for c in cands:
        k = (c.kind, c.redacted, c.source)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(c)
    findings: list[SecretFinding] = []
    for c in uniq[:max_candidates]:
        t = triage_candidate(client, c)
        findings.append(SecretFinding(kind=c.kind, source=c.source, line=c.line,
                                      redacted=c.redacted, triage=t, score=_score(c, t)))
    findings.sort(key=lambda f: -f.score)
    return findings


def _read_js_dir(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in sorted(root.rglob("*.js")):
        if any(p in str(f).lower() for p in ("node_modules", ".min.js.map")):
            continue
        try:
            out[str(f.relative_to(root))] = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
    return out


def main(argv=None) -> int:
    import argparse
    import json
    from dotenv import load_dotenv

    load_dotenv()
    from .client import DeepSeekClient
    from .config import DeepSeekConfig

    ap = argparse.ArgumentParser(prog="python -m aegis.ai.js_secret_hunt",
                                 description="AI triage of hardcoded secrets in JS (local, analytical only)")
    ap.add_argument("--dir", required=True, help="directory of already-acquired, in-scope .js files")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    root = Path(args.dir)
    if not root.is_dir():
        print(f"not a directory: {root}")
        return 2
    sources = _read_js_dir(root)
    if not sources:
        print("no .js files found")
        return 0
    with DeepSeekClient(DeepSeekConfig.from_env()) as client:
        findings = hunt_js_secrets(sources, client)
    real = [f for f in findings if f.triage.verdict == "secret" and not f.triage.is_public_client_key]
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=1))
    else:
        print(f"scanned {len(sources)} JS files -> {len(findings)} candidates, "
              f"{len(real)} likely-real secret(s)\n")
        for f in findings[:25]:
            t = f.triage
            flag = ">>" if (t.verdict == "secret" and not t.is_public_client_key) else "  "
            print(f"{flag} [{t.severity:8}] {f.kind:24} {f.source}:{f.line}  {f.redacted}")
            print(f"     verdict={t.verdict} live~{t.likely_live:.2f} conf={t.confidence:.2f} — {t.reason[:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
