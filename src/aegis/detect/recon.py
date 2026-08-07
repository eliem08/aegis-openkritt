"""Passive-ish recon worker — endpoint & surface discovery (§3 MAP; P1 #13/#14).

Through the gated (scope-enforcing) client, discovers routes from robots.txt,
sitemap.xml, the home page / linked JS, and an OpenAPI/Swagger spec if one is
served. Emits an ``AttackSurface`` the detectors then work against — so the
pipeline maps its own surface instead of relying on hand-fed endpoints.

All requests are GETs through the scope proxy; nothing is modified.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from aegis.model import Asset, AttackSurface, Parameter, ParameterLocation, Route
from aegis.orchestrator import WorkerContext, WorkerResult
from aegis.policy import normalize_host

from .base import DetectorContext, GateFn

# Conservative: quoted absolute paths in HTML/JS.
_PATH_RE = re.compile(r"""["'](/[A-Za-z0-9_\-./]{1,120}?)["']""")
_JS_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js)["']""", re.IGNORECASE)
_ROBOTS_RE = re.compile(r"(?im)^(?:allow|disallow):\s*(/[^\s#*$]*)")
_LOC_RE = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.IGNORECASE)

SPEC_PATHS = ["/openapi.json", "/swagger.json", "/v1/openapi.json", "/api/openapi.json"]
_MAX_ROUTES = 200

_LOCATION_MAP = {
    "query": ParameterLocation.QUERY,
    "path": ParameterLocation.PATH,
    "header": ParameterLocation.HEADER,
    "cookie": ParameterLocation.COOKIE,
}


def extract_paths(text: str | None) -> set[str]:
    if not text:
        return set()
    return {p for p in _PATH_RE.findall(text) if not p.startswith("//")}


def parse_openapi(spec: dict) -> list[Route]:
    routes: list[Route] = []
    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            params = []
            for p in (op or {}).get("parameters", []) if isinstance(op, dict) else []:
                loc = _LOCATION_MAP.get(str(p.get("in", "query")).lower(), ParameterLocation.QUERY)
                params.append(Parameter(name=p.get("name", "?"), location=loc))
            routes.append(Route(method=method.upper(), path=path, parameters=params))
    return routes


class ReconWorker:
    name = "recon"

    def __init__(
        self,
        *,
        client_factory: Callable[[str], httpx.Client],
        gate: GateFn | None = None,
        base_url_for: Callable[[str], str] | None = None,
    ) -> None:
        self._client_factory = client_factory
        self._gate = gate
        self._base_url_for = base_url_for

    def run(self, action, ctx_orch: WorkerContext) -> WorkerResult:
        try:
            host = normalize_host(action.target)
        except ValueError:
            host = action.target
        base_url = self._base_url_for(action.target) if self._base_url_for else f"https://{host}"
        client = self._client_factory(action.target)
        ctx = DetectorContext(
            base_url=base_url, client=client,
            action=action.action or "passive_discovery", gate=self._gate, params=action.params,
        )

        paths: set[str] = set()
        spec_routes: list[Route] = []
        technologies: list[str] = []
        try:
            paths |= self._from_text_endpoints(ctx)
            paths |= self._from_javascript(ctx)
            spec_routes = self._from_spec(ctx)
            technologies = self._fingerprint(ctx)
        finally:
            client.close()

        routes = [Route(method="GET", path=p) for p in sorted(paths)][:_MAX_ROUTES]
        routes += spec_routes[:_MAX_ROUTES]
        asset = Asset(host=host, routes=routes, technologies=technologies)
        return WorkerResult(
            surface_delta=AttackSurface(assets=[asset]),
            notes=f"recon: {len(routes)} routes, {len(technologies)} tech",
        )

    def _safe_get(self, ctx: DetectorContext, path: str) -> httpx.Response | None:
        try:
            return ctx.get(path)
        except Exception:
            return None

    def _from_text_endpoints(self, ctx: DetectorContext) -> set[str]:
        found: set[str] = set()
        robots = self._safe_get(ctx, "/robots.txt")
        if robots is not None and robots.status_code == 200:
            found |= {p for p in _ROBOTS_RE.findall(robots.text)}
        sitemap = self._safe_get(ctx, "/sitemap.xml")
        if sitemap is not None and sitemap.status_code == 200:
            for loc in _LOC_RE.findall(sitemap.text):
                path = urlsplit(loc).path
                if path and path != "/":
                    found.add(path)
        home = self._safe_get(ctx, "/")
        if home is not None and home.status_code == 200:
            found |= extract_paths(home.text)
        return found

    def _from_javascript(self, ctx: DetectorContext) -> set[str]:
        home = self._safe_get(ctx, "/")
        if home is None or home.status_code != 200:
            return set()
        found: set[str] = set()
        for src in _JS_SRC_RE.findall(home.text)[:5]:  # bounded
            if src.startswith("http") and ctx.host not in src:
                continue  # off-host script; skip (scope proxy would block anyway)
            resp = self._safe_get(ctx, src)
            if resp is not None and resp.status_code == 200:
                found |= extract_paths(resp.text)
        return found

    def _from_spec(self, ctx: DetectorContext) -> list[Route]:
        for sp in SPEC_PATHS:
            resp = self._safe_get(ctx, sp)
            if resp is None or resp.status_code != 200:
                continue
            if "json" not in resp.headers.get("content-type", ""):
                continue
            try:
                return parse_openapi(resp.json())
            except Exception:
                continue
        return []

    def _fingerprint(self, ctx: DetectorContext) -> list[str]:
        resp = self._safe_get(ctx, "/")
        if resp is None:
            return []
        tech = []
        server = resp.headers.get("server")
        if server:
            tech.append(server)
        powered = resp.headers.get("x-powered-by")
        if powered:
            tech.append(powered)
        return tech
