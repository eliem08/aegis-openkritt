"""Clean-room API route discovery (Phase 3 §Clean-room API route discovery).

Two pieces, both written from scratch — no AGPL Kiterunner source, wordlists, or
datasets are copied or bundled:

* An **Aegis route schema** (method, template path, header/query/path/body fields,
  content type, source, risk annotations) populated from *owned or permissively
  licensed* OpenAPI documents and the engagement's already-discovered routes.
* A bounded **enumerator** that confirms which schema routes actually exist. It
  establishes a wildcard/catch-all baseline first (so a host that answers 200 for
  everything cannot manufacture false positives), watches target health, and
  quarantines a host after repeated instability or rate-limiting.

The enumerator is transport-agnostic (drives a ``probe(method, path)`` callable)
and confirms existence with a **safe method only** — it never sends a
state-changing request during discovery, whatever method the schema records.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from enum import Enum

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# A response with one of these statuses means the path is genuinely absent.
ABSENT_STATUSES = frozenset({404, 410})
# Statuses that still confirm a route exists (auth required, wrong method, ...).
EXISTS_EVEN_IF_GUARDED = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 422})

_TEMPLATE_FIELD = re.compile(r"\{([^}]+)\}")


class RouteSource(str, Enum):
    OPENAPI = "openapi"
    DISCOVERED = "discovered"
    GENERATED = "generated"


class RouteRisk(str, Enum):
    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"
    SENSITIVE = "sensitive"
    ADMIN = "admin"


@dataclass(frozen=True)
class RouteField:
    name: str
    location: str            # query | path | header | body
    required: bool = False


@dataclass(frozen=True)
class RouteSpec:
    method: str
    path_template: str       # e.g. /users/{id}
    content_type: str = ""
    fields: tuple[RouteField, ...] = ()
    sources: tuple[str, ...] = ()
    risks: frozenset[RouteRisk] = frozenset()

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {_normalize_path(self.path_template)}"

    @property
    def is_state_changing(self) -> bool:
        return self.method.upper() in STATE_CHANGING_METHODS


class RouteSchema:
    """A deduplicated set of route specs keyed by ``METHOD normalized-path``."""

    def __init__(self, routes: Iterable[RouteSpec] = ()) -> None:
        self._by_key: dict[str, RouteSpec] = {}
        for route in routes:
            self.add(route)

    def add(self, route: RouteSpec) -> None:
        existing = self._by_key.get(route.key)
        self._by_key[route.key] = _merge_routes(existing, route) if existing else route

    def __iter__(self) -> Iterator[RouteSpec]:
        return iter(self._by_key.values())

    def __len__(self) -> int:
        return len(self._by_key)

    def merge(self, other: RouteSchema) -> RouteSchema:
        for route in other:
            self.add(route)
        return self

    # -- population ---------------------------------------------------------

    @classmethod
    def from_openapi(cls, document: dict) -> RouteSchema:
        """Build a schema from an OpenAPI 3 document (owned/permissive only)."""
        schema = cls()
        for path, item in (document.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            shared = _params_from(item.get("parameters"))
            for method, operation in item.items():
                if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                    continue
                fields = list(shared) + list(_params_from(operation.get("parameters")))
                content_type, body_fields = _body_from(operation.get("requestBody"))
                fields.extend(body_fields)
                schema.add(RouteSpec(
                    method=method.upper(), path_template=path, content_type=content_type,
                    fields=tuple(fields), sources=(RouteSource.OPENAPI.value,),
                    risks=_risks(method, path),
                ))
        return schema

    @classmethod
    def from_discovered(cls, routes: Iterable) -> RouteSchema:
        """Build a schema from discovered route assets (method, path, host)."""
        schema = cls()
        for route in routes:
            method = str(_attr(route, "method", "GET")).upper()
            path = str(_attr(route, "path", "/"))
            params = _attr(route, "parameters", []) or []
            fields = tuple(
                RouteField(str(p.get("name")), str(p.get("location", "query")))
                for p in params if isinstance(p, dict) and p.get("name")
            )
            schema.add(RouteSpec(
                method=method, path_template=path, fields=fields,
                sources=(RouteSource.DISCOVERED.value,), risks=_risks(method, path),
            ))
        return schema


# --- enumeration -----------------------------------------------------------

@dataclass(frozen=True)
class ProbeResponse:
    status: int              # 0 signals a connection error
    body: str = ""
    error: bool = False


@dataclass
class EnumConfig:
    safe_probe_method: str = "GET"       # never a state-changing method during discovery
    wildcard_probes: int = 3
    max_requests: int = 800
    max_errors_per_host: int = 5
    max_redirects: int = 2
    rate_limit_statuses: tuple[int, ...] = (429, 503)
    canary_value: str = "aegis-canary-7f3a"


class HostHealth(str, Enum):
    HEALTHY = "healthy"
    CATCH_ALL = "catch_all"      # answers success for everything; FPs suppressed
    UNSTABLE = "unstable"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class RouteObservation:
    method: str
    path: str
    host: str
    status: int
    present: bool
    evidence: str
    sources: tuple[str, ...]
    risks: tuple[str, ...]


@dataclass
class EnumerationResult:
    host: str
    health: HostHealth
    routes: list[RouteObservation]       # present routes only
    suppressed: int                      # probed but absent / catch-all suppressed
    requests: int
    complete: bool
    reason: str = ""

    @property
    def present_paths(self) -> set[str]:
        return {r.path for r in self.routes}


@dataclass(frozen=True)
class _Baseline:
    kind: str                 # not_found | catch_all | unstable
    signature: tuple = ()


class RouteEnumerator:
    def __init__(self, probe: Callable[[str, str], ProbeResponse], *, host: str,
                 config: EnumConfig | None = None) -> None:
        self._probe_fn = probe
        self.host = host
        self.config = config or EnumConfig()
        self._requests = 0
        self._errors = 0

    def enumerate(self, schema: RouteSchema) -> EnumerationResult:
        baseline = self._establish_baseline()
        if baseline.kind == "quarantined":
            return self._result(HostHealth.QUARANTINED, [], 0, complete=False,
                                reason="host_unhealthy_before_start")
        health = {"catch_all": HostHealth.CATCH_ALL, "unstable": HostHealth.UNSTABLE}.get(
            baseline.kind, HostHealth.HEALTHY)

        found: list[RouteObservation] = []
        suppressed = 0
        reason = ""
        # One existence probe per unique concretized path; attribute to every
        # schema route on that path (fewer requests, and never method-specific
        # state-changing traffic).
        by_path = _group_by_concrete_path(schema, self.config.canary_value)
        for concrete_path, specs in by_path.items():
            if self._requests >= self.config.max_requests:
                reason = "request_budget"
                break
            resp = self._probe(concrete_path)
            if self._is_unhealthy(resp):
                self._errors += 1
                if self._errors >= self.config.max_errors_per_host:
                    return self._result(HostHealth.QUARANTINED, found, suppressed,
                                        complete=False, reason="host_quarantined")
                suppressed += len(specs)
                continue
            present, evidence = self._decide(resp, baseline)
            for spec in specs:
                obs = RouteObservation(
                    method=spec.method, path=spec.path_template, host=self.host,
                    status=resp.status, present=present, evidence=evidence,
                    sources=spec.sources, risks=tuple(r.value for r in sorted(spec.risks, key=lambda x: x.value)),
                )
                if present:
                    found.append(obs)
                else:
                    suppressed += 1
        complete = reason == "" and health is not HostHealth.UNSTABLE
        if health is HostHealth.UNSTABLE and not reason:
            reason = "unstable_host"
        return self._result(health, found, suppressed, complete=complete, reason=reason)

    # -- baselines + health -------------------------------------------------

    def _establish_baseline(self) -> _Baseline:
        sigs = []
        for i in range(self.config.wildcard_probes):
            # A path that cannot legitimately exist.
            resp = self._probe(f"/{self.config.canary_value}/nonexistent-{i}")
            if self._is_unhealthy(resp):
                self._errors += 1
                if self._errors >= self.config.max_errors_per_host:
                    return _Baseline("quarantined")
                continue
            sigs.append(_signature(resp))
        if not sigs:
            return _Baseline("quarantined")

        statuses = {s[0] for s in sigs}
        if statuses <= ABSENT_STATUSES:
            return _Baseline("not_found")
        # Success for random paths => catch-all, but only if the signature is stable.
        if statuses <= {200, 201, 202, 203, 204} and len(set(sigs)) == 1:
            return _Baseline("catch_all", sigs[0])
        return _Baseline("unstable")

    def _decide(self, resp: ProbeResponse, baseline: _Baseline) -> tuple[bool, str]:
        if baseline.kind == "catch_all":
            if _signature(resp) != baseline.signature:
                return True, "differs from catch-all baseline"
            return False, "matches catch-all (suppressed)"
        if baseline.kind == "unstable":
            # Only an unambiguous non-absent status counts on a noisy host.
            if resp.status in EXISTS_EVEN_IF_GUARDED:
                return True, f"status {resp.status} on unstable host"
            return False, "indistinguishable on unstable host"
        # not_found baseline: anything that is not clearly absent exists.
        if resp.status in ABSENT_STATUSES:
            return False, f"status {resp.status}"
        if resp.status in EXISTS_EVEN_IF_GUARDED:
            return True, f"status {resp.status}"
        return False, f"inconclusive status {resp.status}"

    def _is_unhealthy(self, resp: ProbeResponse) -> bool:
        return (resp.error or resp.status == 0 or resp.status >= 500
                or resp.status in self.config.rate_limit_statuses)

    def _probe(self, path: str) -> ProbeResponse:
        self._requests += 1
        return self._probe_fn(self.config.safe_probe_method, path)

    def _result(self, health, found, suppressed, *, complete, reason) -> EnumerationResult:
        return EnumerationResult(
            host=self.host, health=health, routes=found, suppressed=suppressed,
            requests=self._requests, complete=complete, reason=reason,
        )


# --- helpers ---------------------------------------------------------------

def _normalize_path(path: str) -> str:
    # Template fields are positional, so /users/{id} and /users/{userId} are the
    # same route shape; collapse each field to {}.
    path = "/" + (path or "").strip().lstrip("/")
    return _TEMPLATE_FIELD.sub("{}", path).rstrip("/") or "/"


def _concretize(path: str, canary: str) -> str:
    # Replace each {field} with an owned synthetic value for a real probe.
    return _TEMPLATE_FIELD.sub(canary, "/" + (path or "").strip().lstrip("/"))


def _group_by_concrete_path(schema: RouteSchema, canary: str) -> dict[str, list[RouteSpec]]:
    grouped: dict[str, list[RouteSpec]] = {}
    for spec in schema:
        grouped.setdefault(_concretize(spec.path_template, canary), []).append(spec)
    return grouped


def _signature(resp: ProbeResponse) -> tuple:
    body = resp.body or ""
    return (resp.status, len(body) // 32, len(body.split()))


def _params_from(params) -> list[RouteField]:
    out = []
    for p in params or []:
        if isinstance(p, dict) and p.get("name"):
            out.append(RouteField(str(p["name"]), str(p.get("in", "query")), bool(p.get("required", False))))
    return out


def _body_from(request_body) -> tuple[str, list[RouteField]]:
    if not isinstance(request_body, dict):
        return "", []
    content = request_body.get("content") or {}
    if not content:
        return "", []
    content_type = next(iter(content))
    schema = (content.get(content_type) or {}).get("schema") or {}
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    fields = [RouteField(str(name), "body", name in required) for name in props]
    return content_type, fields


def _risks(method: str, path: str) -> frozenset[RouteRisk]:
    risks = {RouteRisk.STATE_CHANGING if method.upper() in STATE_CHANGING_METHODS
             else RouteRisk.READ_ONLY}
    low = (path or "").lower()
    if any(seg in low for seg in ("admin", "internal", "superuser", "manage", "root")):
        risks.add(RouteRisk.ADMIN)
    if any(seg in low for seg in ("token", "secret", "key", "password", "cred",
                                  "private", "ssn", "payment", "billing")):
        risks.add(RouteRisk.SENSITIVE)
    return frozenset(risks)


def _merge_routes(a: RouteSpec, b: RouteSpec) -> RouteSpec:
    fields = tuple({(f.name, f.location): f for f in (*a.fields, *b.fields)}.values())
    return RouteSpec(
        method=a.method, path_template=a.path_template,
        content_type=a.content_type or b.content_type, fields=fields,
        sources=tuple(sorted(set(a.sources) | set(b.sources))),
        risks=a.risks | b.risks,
    )


def _attr(obj, name, default):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)
