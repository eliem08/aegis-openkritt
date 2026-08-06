"""Operator-gated JS discovery: fetch authorized JS URLs, hand off to the secret lane.

This is the acquisition step in front of ``js_secret_hunt``. Because it reaches LIVE
hosts, it carries the same discipline as the web lane (see [[live-attack-boundary]]):

* It runs ONLY when the operator explicitly asserts authorization (``authorized=True``).
* It fetches ONLY the exact URLs the operator supplies — it never crawls, never expands
  to other paths or hosts, and does not follow cross-host redirects (a redirect off the
  requested host is dropped, so scope can't silently widen).
* It is a plain GET of a JavaScript asset — no attack payloads. Size/timeout capped.

Aegis assembles and drives this; the operator authorizes the target and owns the list.
The fetched JS is passed to the analytical secret triage, which never uses a found key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit


class DiscoveryError(RuntimeError):
    """Refused: no authorization, or nothing fetchable."""


@dataclass
class FetchScope:
    urls: list[str]
    authorized: bool = False           # the operator asserts they may fetch these
    max_bytes: int = 3_000_000
    timeout: float = 15.0
    user_agent: str = "aegis-research (authorized recon)"

    def hosts(self) -> set[str]:
        return {(urlsplit(u).hostname or "").lower() for u in self.urls if u}


# fetcher(url, timeout, user_agent) -> (status_code:int, final_host:str, content_type:str, text:str)
Fetcher = Callable[[str, float, str], tuple]


def _httpx_fetcher(url: str, timeout: float, ua: str) -> tuple:
    import httpx

    r = httpx.get(url, timeout=timeout, follow_redirects=False,
                  headers={"User-Agent": ua, "Accept": "application/javascript, text/javascript, */*"})
    final_host = (urlsplit(str(r.url)).hostname or "").lower()
    return r.status_code, final_host, r.headers.get("content-type", ""), r.text


def fetch_js(scope: FetchScope, *, fetcher: Fetcher | None = None) -> dict[str, str]:
    """Fetch each authorized JS URL. Returns {url: js_text}. Confined to the exact URLs;
    cross-host redirects and non-JS responses are dropped."""
    if not scope.authorized:
        raise DiscoveryError(
            "js discovery refused: scope.authorized is False. This fetches live hosts — "
            "only run it against URLs you are authorized to test, and supply them explicitly."
        )
    fetch = fetcher or _httpx_fetcher
    out: dict[str, str] = {}
    for url in scope.urls:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        req_host = parts.hostname.lower()
        try:
            status, final_host, ctype, text = fetch(url, scope.timeout, scope.user_agent)
        except Exception:
            continue
        if status != 200:
            continue
        if final_host and final_host != req_host:      # redirected off the requested host -> drop
            continue
        looks_js = "javascript" in (ctype or "").lower() or url.split("?")[0].endswith(".js")
        if not looks_js:
            continue
        out[url] = (text or "")[: scope.max_bytes]
    return out


def discover_and_triage(scope: FetchScope, client, *, fetcher: Fetcher | None = None) -> list:
    """Fetch authorized JS, then run the analytical secret triage. Returns SecretFinding list."""
    from .js_secret_hunt import hunt_js_secrets

    sources = fetch_js(scope, fetcher=fetcher)
    if not sources:
        return []
    return hunt_js_secrets(sources, client)


def main(argv=None) -> int:
    import argparse
    import json
    from pathlib import Path

    from dotenv import load_dotenv

    load_dotenv()
    from .client import DeepSeekClient
    from .config import DeepSeekConfig

    ap = argparse.ArgumentParser(
        prog="python -m aegis.ai.js_discovery",
        description="Fetch AUTHORIZED JS URLs and triage them for hardcoded secrets.")
    ap.add_argument("--urls-file", help="file with one authorized JS URL per line")
    ap.add_argument("--url", action="append", default=[], help="an authorized JS URL (repeatable)")
    ap.add_argument("--authorized", action="store_true",
                    help="REQUIRED: assert you are authorized to fetch these exact URLs")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    urls = list(args.url)
    if args.urls_file:
        urls += [ln.strip() for ln in Path(args.urls_file).read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
    if not urls:
        print("no URLs supplied (use --url or --urls-file)")
        return 2
    if not args.authorized:
        print("refused: pass --authorized to confirm you may fetch these exact URLs")
        return 3
    scope = FetchScope(urls=urls, authorized=True)
    with DeepSeekClient(DeepSeekConfig.from_env()) as client:
        findings = discover_and_triage(scope, client)
    real = [f for f in findings if f.triage.verdict == "secret" and not f.triage.is_public_client_key]
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=1))
    else:
        print(f"fetched {len(scope.urls)} URL(s) -> {len(findings)} candidates, "
              f"{len(real)} likely-real secret(s)\n")
        for f in findings[:25]:
            t = f.triage
            flag = ">>" if (t.verdict == "secret" and not t.is_public_client_key) else "  "
            print(f"{flag} [{t.severity:8}] {f.kind:22} {f.source}:{f.line}  {f.redacted}  "
                  f"({t.verdict}, live~{t.likely_live:.2f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
