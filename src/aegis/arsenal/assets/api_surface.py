"""API techniques: spec ingestion, authorization matrix, BOLA/IDOR, mass assignment.

The authorization work here is built around contrast, which is the only way to tell
a real broken-access-control bug from an endpoint that simply returns public data:
the *same* request is issued as identity A, as identity B, and unauthenticated, and
only a response that identity B should not be able to obtain — while a comparable
guarded endpoint on the same API correctly refuses it — is reported.

Aegis never authenticates. The operator logs each role in themselves and hands the
resulting header material over as an ``Identity``; without at least two identities
the cross-role techniques report ``WAITING_FOR_PREREQUISITE`` rather than guessing.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .context import LaneContext
from .results import (
    Observation,
    TechniqueResult,
    deduplicate,
    executed,
    now,
    unavailable,
    waiting,
)
from .scope import OutOfScopeError
from .session import BudgetExhausted, StateChangeRefused

#: Path parameter names that address a specific object; these are the BOLA surface.
#: Matches ``id``, ``user_id``, ``userId``, and ``orgUuid`` alike — snake_case and
#: camelCase both appear in real specs and both address a specific object.
_OBJECT_PARAM = re.compile(
    r"(?:^|_|(?<=[a-z0-9]))(id|uuid|guid|key|ref|number|slug|handle|account|user|org|"
    r"tenant|customer|invoice|order|document|file|project|team|member)s?$",
    re.IGNORECASE,
)

#: Properties a client should never be able to set. Their presence in a writable
#: request schema is the mass-assignment surface.
PRIVILEGED_PROPERTIES: frozenset[str] = frozenset({
    "id", "role", "roles", "is_admin", "isadmin", "admin", "is_staff", "isstaff",
    "permissions", "scopes", "scope", "owner", "owner_id", "ownerid", "user_id",
    "userid", "account_id", "accountid", "tenant_id", "tenantid", "organization_id",
    "verified", "is_verified", "email_verified", "balance", "credit", "price",
    "created_at", "updated_at", "deleted_at", "password_hash", "internal",
})

_READ_METHODS = ("get", "head", "options")
_WRITE_METHODS = ("post", "put", "patch", "delete")


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One operation from an OpenAPI document."""

    method: str
    path: str
    operation_id: str = ""
    summary: str = ""
    path_parameters: tuple[str, ...] = ()
    query_parameters: tuple[str, ...] = ()
    request_properties: tuple[str, ...] = ()
    security: tuple[str, ...] = ()
    declared_public: bool = False

    @property
    def read_only(self) -> bool:
        return self.method.lower() in _READ_METHODS

    @property
    def object_parameters(self) -> tuple[str, ...]:
        # search, not match: the object token is a *suffix* in camelCase names
        # ("userId"), where an anchored match would stop at the "user" prefix.
        return tuple(item for item in self.path_parameters if _OBJECT_PARAM.search(item))

    def document(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ApiSpecification:
    """A parsed, normalized OpenAPI/Swagger document."""

    title: str
    version: str
    servers: tuple[str, ...]
    endpoints: tuple[Endpoint, ...]
    global_security: tuple[str, ...] = ()
    source: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def document(self) -> dict[str, Any]:
        return {
            "title": self.title, "version": self.version, "servers": list(self.servers),
            "global_security": list(self.global_security), "source": self.source,
            "endpoint_count": len(self.endpoints),
            "endpoints": [item.document() for item in self.endpoints],
            "warnings": list(self.warnings),
        }


class SpecificationError(ValueError):
    """The supplied document is not a usable OpenAPI/Swagger specification."""


def load_specification(path: str | Path) -> ApiSpecification:
    """Parse an OpenAPI 2/3 document from JSON or YAML.

    YAML needs ``PyYAML``; without it a YAML spec raises ``SpecificationError`` with
    that instruction rather than being silently skipped.
    """
    source = Path(path)
    if not source.is_file():
        raise SpecificationError(f"specification file does not exist: {source}")
    raw = source.read_text(encoding="utf-8")
    document: Any
    if source.suffix.lower() in {".yaml", ".yml"} or not raw.lstrip().startswith("{"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise SpecificationError(
                "this specification is YAML and PyYAML is not installed; "
                "`pip install PyYAML` or supply the JSON form of the spec"
            ) from exc
        try:
            document = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise SpecificationError(f"specification is not valid YAML: {exc}") from exc
    else:
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SpecificationError(f"specification is not valid JSON: {exc}") from exc
    return parse_specification(document, source=str(source))


def parse_specification(document: Any, *, source: str = "") -> ApiSpecification:
    """Normalize a loaded OpenAPI 2/3 mapping into endpoints."""
    if not isinstance(document, Mapping):
        raise SpecificationError("specification root must be a mapping")
    paths = document.get("paths")
    if not isinstance(paths, Mapping) or not paths:
        raise SpecificationError("specification declares no paths")

    info = document.get("info") if isinstance(document.get("info"), Mapping) else {}
    warnings: list[str] = []
    servers = _servers(document, warnings)
    global_security = _security_names(document.get("security"))
    components = document.get("components")
    schemas = (
        components.get("schemas", {}) if isinstance(components, Mapping) else {}
    ) or document.get("definitions", {})
    if not isinstance(schemas, Mapping):
        schemas = {}

    endpoints: list[Endpoint] = []
    for path, operations in paths.items():
        if not isinstance(operations, Mapping):
            continue
        shared = operations.get("parameters") if isinstance(
            operations.get("parameters"), Sequence) else ()
        for method, operation in operations.items():
            if method.lower() not in (*_READ_METHODS, *_WRITE_METHODS):
                continue
            if not isinstance(operation, Mapping):
                continue
            parameters = [*(shared or ()), *(operation.get("parameters") or ())]
            path_params, query_params = _split_parameters(parameters, str(path))
            security = _security_names(operation.get("security"))
            declared_public = (
                operation.get("security") == [] or
                (not security and not global_security)
            )
            endpoints.append(Endpoint(
                method=method.upper(), path=str(path),
                operation_id=str(operation.get("operationId") or ""),
                summary=str(operation.get("summary") or ""),
                path_parameters=path_params, query_parameters=query_params,
                request_properties=_request_properties(operation, schemas, warnings),
                security=security or global_security,
                declared_public=bool(declared_public),
            ))
    if not endpoints:
        raise SpecificationError("specification contains no recognizable operations")
    return ApiSpecification(
        title=str(info.get("title") or "untitled API"),
        version=str(info.get("version") or ""), servers=servers,
        endpoints=tuple(endpoints), global_security=global_security, source=source,
        warnings=tuple(warnings),
    )


def _servers(document: Mapping[str, Any], warnings: list[str]) -> tuple[str, ...]:
    servers = document.get("servers")
    if isinstance(servers, Sequence) and not isinstance(servers, (str, bytes)):
        urls = tuple(
            str(item.get("url")) for item in servers
            if isinstance(item, Mapping) and item.get("url")
        )
        if urls:
            return urls
    host = document.get("host")
    if host:  # Swagger 2
        schemes = document.get("schemes") or ["https"]
        base = str(document.get("basePath") or "")
        return tuple(f"{scheme}://{host}{base}" for scheme in schemes)
    warnings.append("specification declares no server URL; the asset locator will be used")
    return ()


def _security_names(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    names: list[str] = []
    for entry in value:
        if isinstance(entry, Mapping):
            names.extend(str(key) for key in entry)
    return tuple(dict.fromkeys(names))


def _split_parameters(
    parameters: Sequence[Any], path: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    path_params = [
        str(item.get("name")) for item in parameters
        if isinstance(item, Mapping) and item.get("in") == "path" and item.get("name")
    ]
    query_params = [
        str(item.get("name")) for item in parameters
        if isinstance(item, Mapping) and item.get("in") == "query" and item.get("name")
    ]
    # Templated segments are authoritative even when the spec omits the declaration.
    for token in re.findall(r"\{([^}/]+)\}", path):
        if token not in path_params:
            path_params.append(token)
    return tuple(dict.fromkeys(path_params)), tuple(dict.fromkeys(query_params))


def _request_properties(
    operation: Mapping[str, Any], schemas: Mapping[str, Any], warnings: list[str],
) -> tuple[str, ...]:
    body = operation.get("requestBody")
    schema: Any = None
    if isinstance(body, Mapping):
        content = body.get("content")
        if isinstance(content, Mapping):
            for media in ("application/json", "application/x-www-form-urlencoded"):
                entry = content.get(media)
                if isinstance(entry, Mapping) and isinstance(entry.get("schema"), Mapping):
                    schema = entry["schema"]
                    break
    if schema is None:  # Swagger 2 body parameter
        for item in operation.get("parameters") or ():
            if isinstance(item, Mapping) and item.get("in") == "body":
                schema = item.get("schema")
                break
    resolved = _resolve_schema(schema, schemas, warnings, depth=0)
    properties = resolved.get("properties") if isinstance(resolved, Mapping) else None
    if not isinstance(properties, Mapping):
        return ()
    return tuple(str(key) for key in properties)


def _resolve_schema(
    schema: Any, schemas: Mapping[str, Any], warnings: list[str], *, depth: int,
) -> Mapping[str, Any]:
    if not isinstance(schema, Mapping) or depth > 5:
        return {}
    reference = schema.get("$ref")
    if isinstance(reference, str):
        name = reference.rsplit("/", 1)[-1]
        target = schemas.get(name)
        if not isinstance(target, Mapping):
            warnings.append(f"unresolved schema reference: {reference}")
            return {}
        return _resolve_schema(target, schemas, warnings, depth=depth + 1)
    for keyword in ("allOf", "oneOf", "anyOf"):
        members = schema.get(keyword)
        if isinstance(members, Sequence) and not isinstance(members, (str, bytes)):
            merged: dict[str, Any] = {"properties": {}}
            for member in members:
                part = _resolve_schema(member, schemas, warnings, depth=depth + 1)
                if isinstance(part.get("properties"), Mapping):
                    merged["properties"].update(part["properties"])
            if merged["properties"]:
                return merged
    return schema


def _specification(context: LaneContext) -> ApiSpecification | None:
    if context.specification_path is None:
        return None
    return load_specification(context.specification_path)


# ------------------------------------------------------------------- techniques

def ingest_specification(context: LaneContext) -> TechniqueResult:
    """Parse the spec and inventory the endpoints, parameters, and declared auth."""
    technique = "openapi-ingest"
    started = now()
    if context.specification_path is None:
        return waiting(
            technique, context.asset,
            "no OpenAPI/Swagger document supplied; pass --api-spec to enumerate endpoints",
        )
    try:
        specification = _specification(context)
    except SpecificationError as exc:
        return unavailable(technique, context.asset, str(exc), tool="aegis-openapi-parser")
    assert specification is not None

    unauthenticated = [
        item for item in specification.endpoints
        if item.declared_public and not item.read_only
    ]
    observations = [
        Observation(
            technique, "Write operation declares no authentication requirement", "medium",
            f"{item.method} {item.path}",
            evidence={"operation_id": item.operation_id, "summary": item.summary},
            guarded_sibling=(
                "comparable write operations in this spec declare a security scheme"
                if any(other.security for other in specification.endpoints
                       if not other.read_only) else ""
            ),
            weakness="missing-declared-authentication",
            recommendation="confirm against the live endpoint; a spec omission is not proof",
        )
        for item in unauthenticated
    ] if any(item.security for item in specification.endpoints) else []
    return executed(
        technique, context.asset, deduplicate(observations), tool="aegis-openapi-parser",
        started_at=started, metadata=specification.document(),
    )


def _endpoint_url(context: LaneContext, specification: ApiSpecification,
                  endpoint: Endpoint, values: Mapping[str, str]) -> str:
    base = (specification.servers[0] if specification.servers else context.base_url())
    if not base.startswith(("http://", "https://")):
        base = "https://" + base.lstrip("/")
    path = endpoint.path
    for name, value in values.items():
        path = path.replace("{" + name + "}", str(value))
    return base.rstrip("/") + "/" + path.lstrip("/")


def authorization_matrix(context: LaneContext) -> TechniqueResult:
    """Issue each read endpoint as every identity and unauthenticated, and contrast.

    Only read-only methods are exercised, and only endpoints with no unresolved path
    parameter — a matrix built on invented object identifiers proves nothing.
    """
    technique = "authorization-matrix"
    started = now()
    if context.specification_path is None:
        return waiting(technique, context.asset, "an OpenAPI document is required")
    if len(context.identities) < 2:
        return waiting(
            technique, context.asset,
            "the authorization matrix needs at least two operator-supplied identities "
            "(authenticate each role yourself and pass its headers with --identity); "
            "Aegis does not log in or create accounts",
        )
    try:
        specification = _specification(context)
    except SpecificationError as exc:
        return unavailable(technique, context.asset, str(exc), tool="aegis-authz-matrix")
    assert specification is not None

    candidates = [
        item for item in specification.endpoints
        if item.read_only and not item.path_parameters
    ]
    if not candidates:
        return executed(
            technique, context.asset, (), tool="aegis-authz-matrix", started_at=started,
            reason="no parameter-free read endpoints to contrast without invented identifiers",
        )
    matrix: list[dict[str, Any]] = []
    observations: list[Observation] = []
    requests_made = 0
    for endpoint in candidates[: int(context.option("max_endpoints", 25))]:
        url = _endpoint_url(context, specification, endpoint, {})
        row: dict[str, Any] = {"endpoint": f"{endpoint.method} {endpoint.path}", "results": {}}
        for label, headers in (
            ("anonymous", {}),
            *((item.label, dict(item.headers)) for item in context.identities),
        ):
            try:
                response = context.session.request(
                    endpoint.method, url, technique_id=technique, headers=headers,
                )
            except BudgetExhausted:
                row["results"][label] = {"outcome": "budget_exhausted"}
                matrix.append(row)
                return _matrix_result(
                    technique, context, observations, matrix, requests_made, started,
                    reason="request budget was exhausted before the matrix completed",
                )
            except (OutOfScopeError, StateChangeRefused) as exc:
                row["results"][label] = {"outcome": "refused", "reason": str(exc)}
                continue
            except OSError as exc:
                row["results"][label] = {"outcome": "error", "reason": str(exc)}
                continue
            requests_made += 1
            row["results"][label] = {
                "status_code": response.status_code, "bytes": len(response.body),
            }
        matrix.append(row)
        observations.extend(_matrix_observations(technique, endpoint, url, row, specification))
    return _matrix_result(
        technique, context, observations, matrix, requests_made, started,
    )


def _matrix_result(technique, context, observations, matrix, requests_made, started,
                   *, reason: str = "") -> TechniqueResult:
    return executed(
        technique, context.asset, deduplicate(observations), tool="aegis-authz-matrix",
        requests_made=requests_made, started_at=started, reason=reason,
        metadata={"matrix": matrix},
    )


def _matrix_observations(
    technique: str, endpoint: Endpoint, url: str, row: Mapping[str, Any],
    specification: ApiSpecification,
) -> list[Observation]:
    results = row.get("results") or {}
    anonymous = results.get("anonymous") or {}
    anonymous_status = anonymous.get("status_code")
    if anonymous_status is None or anonymous_status >= 400:
        return []
    if not endpoint.security:
        return []  # spec says it is public and it behaves publicly: consistent, not a bug.
    guarded = [
        f"{item.method} {item.path}" for item in specification.endpoints
        if item.security and item is not endpoint
    ]
    return [Observation(
        technique, "Endpoint declaring authentication served an unauthenticated request",
        "high", f"{endpoint.method} {endpoint.path}",
        evidence={
            "url": url, "anonymous_status": anonymous_status,
            "anonymous_bytes": anonymous.get("bytes"),
            "declared_security": list(endpoint.security),
            "authenticated_results": {
                key: value for key, value in results.items() if key != "anonymous"
            },
        },
        guarded_sibling=(
            f"sibling operations declaring the same scheme ({guarded[:3]}) are the contrast"
            if guarded else ""
        ),
        weakness="broken-authentication",
        recommendation="verify the body actually contains protected data before reporting; "
                       "a 200 with an empty or public payload is not an authz break",
    )]


def object_reference_probe(context: LaneContext) -> TechniqueResult:
    """Probe object identifiers across an identity boundary (BOLA/IDOR).

    Requires the operator to supply, per identity, at least one object identifier
    that identity legitimately owns. Guessing identifiers produces noise and can
    touch other researchers' or real users' data, so absent that input the technique
    reports its prerequisite instead of inventing values.
    """
    technique = "object-reference-probe"
    started = now()
    if context.specification_path is None:
        return waiting(technique, context.asset, "an OpenAPI document is required")
    if len(context.identities) < 2:
        return waiting(
            technique, context.asset,
            "BOLA probing needs two operator-supplied identities so an object owned by "
            "one can be requested as the other",
        )
    owned: Mapping[str, Mapping[str, str]] = context.option("owned_objects", {}) or {}
    if len(owned) < 2:
        return waiting(
            technique, context.asset,
            "supply each identity's own object identifiers via --owned-object "
            "(label=param=value); Aegis will not guess identifiers belonging to "
            "unknown third parties",
        )
    try:
        specification = _specification(context)
    except SpecificationError as exc:
        return unavailable(technique, context.asset, str(exc), tool="aegis-bola-probe")
    assert specification is not None

    labels = [item.label for item in context.identities if item.label in owned]
    if len(labels) < 2:
        return waiting(
            technique, context.asset,
            "the supplied object identifiers do not cover at least two named identities",
        )
    headers_by_label = {item.label: dict(item.headers) for item in context.identities}
    observations: list[Observation] = []
    probes: list[dict[str, Any]] = []
    requests_made = 0
    candidates = [
        item for item in specification.endpoints if item.read_only and item.object_parameters
    ]
    for endpoint in candidates[: int(context.option("max_endpoints", 25))]:
        for owner in labels:
            values = {
                name: owned[owner][name] for name in endpoint.path_parameters
                if name in owned[owner]
            }
            if len(values) != len(endpoint.path_parameters):
                continue
            url = _endpoint_url(context, specification, endpoint, values)
            row: dict[str, Any] = {
                "endpoint": f"{endpoint.method} {endpoint.path}", "owner": owner,
                "results": {},
            }
            for label in labels:
                try:
                    response = context.session.request(
                        endpoint.method, url, technique_id=technique,
                        headers=headers_by_label[label],
                    )
                except BudgetExhausted:
                    probes.append(row)
                    return executed(
                        technique, context.asset, deduplicate(observations),
                        tool="aegis-bola-probe", requests_made=requests_made,
                        started_at=started,
                        reason="request budget exhausted before probing completed",
                        metadata={"probes": probes},
                    )
                except (OutOfScopeError, StateChangeRefused, OSError) as exc:
                    row["results"][label] = {"outcome": "refused", "reason": str(exc)}
                    continue
                requests_made += 1
                row["results"][label] = {
                    "status_code": response.status_code, "bytes": len(response.body),
                }
            probes.append(row)
            observations.extend(_bola_observations(technique, endpoint, url, owner, row))
    return executed(
        technique, context.asset, deduplicate(observations), tool="aegis-bola-probe",
        requests_made=requests_made, started_at=started, metadata={"probes": probes},
    )


def _bola_observations(
    technique: str, endpoint: Endpoint, url: str, owner: str, row: Mapping[str, Any],
) -> list[Observation]:
    results = row.get("results") or {}
    owner_result = results.get(owner) or {}
    owner_status = owner_result.get("status_code")
    if owner_status is None or owner_status >= 400:
        return []  # the owner cannot read it either: nothing to cross.
    output: list[Observation] = []
    for label, result in results.items():
        if label == owner or not isinstance(result, Mapping):
            continue
        status = result.get("status_code")
        if status is None or status >= 400:
            continue
        if result.get("bytes") != owner_result.get("bytes"):
            continue  # a different body is likely that identity's own object.
        output.append(Observation(
            technique, "Object owned by one identity is readable by another", "high",
            f"{endpoint.method} {endpoint.path}",
            evidence={
                "url": url, "owner_identity": owner, "crossing_identity": label,
                "owner_status": owner_status, "crossing_status": status,
                "byte_length_match": True,
            },
            guarded_sibling=(
                f"identity {label} receives a distinct response on objects it owns, so the "
                "byte-identical response here is the same record, not a coincidence"
            ),
            weakness="broken-object-level-authorization",
            recommendation="confirm a unique field from the owner's record appears in the "
                           "crossing identity's response body before reporting",
        ))
    return output


def mass_assignment(context: LaneContext) -> TechniqueResult:
    """Flag writable request schemas that accept privileged, normally read-only fields."""
    technique = "mass-assignment"
    started = now()
    if context.specification_path is None:
        return waiting(technique, context.asset, "an OpenAPI document is required")
    try:
        specification = _specification(context)
    except SpecificationError as exc:
        return unavailable(technique, context.asset, str(exc), tool="aegis-openapi-parser")
    assert specification is not None

    observations: list[Observation] = []
    for endpoint in specification.endpoints:
        if endpoint.read_only or not endpoint.request_properties:
            continue
        exposed = sorted(
            name for name in endpoint.request_properties
            if name.lower().replace("-", "_") in PRIVILEGED_PROPERTIES
        )
        if not exposed:
            continue
        observations.append(Observation(
            technique, "Write schema accepts privileged properties", "medium",
            f"{endpoint.method} {endpoint.path}",
            evidence={"privileged_properties": exposed,
                      "all_properties": list(endpoint.request_properties)[:100],
                      "operation_id": endpoint.operation_id},
            guarded_sibling="",
            weakness="mass-assignment",
            recommendation="static surface only; confirm the server actually honors the "
                           "field before reporting, which needs a state-changing request "
                           "and therefore an explicit opt-in",
        ))
    return executed(
        technique, context.asset, deduplicate(observations), tool="aegis-openapi-parser",
        started_at=started,
        metadata={"endpoints_reviewed": len(specification.endpoints)},
    )


def rate_limit_check(context: LaneContext) -> TechniqueResult:
    """Check whether the API signals or enforces any request budget.

    Deliberately gentle: a handful of ordinary reads spaced by the session limiter.
    The goal is to observe rate-limit *signalling*, not to find the breaking point,
    which would be indistinguishable from a denial-of-service attempt.
    """
    technique = "rate-limit-check"
    started = now()
    if context.specification_path is None:
        return waiting(technique, context.asset, "an OpenAPI document is required")
    try:
        specification = _specification(context)
    except SpecificationError as exc:
        return unavailable(technique, context.asset, str(exc), tool="stdlib-http")
    assert specification is not None

    endpoint = next(
        (item for item in specification.endpoints
         if item.read_only and not item.path_parameters), None,
    )
    if endpoint is None:
        return executed(
            technique, context.asset, (), tool="stdlib-http", started_at=started,
            reason="no parameter-free read endpoint available to sample",
        )
    url = _endpoint_url(context, specification, endpoint, {})
    samples = max(2, min(int(context.option("rate_limit_samples", 5)), 10))
    statuses: list[int] = []
    headers_seen: set[str] = set()
    for _ in range(samples):
        try:
            response = context.session.get(url, technique_id=technique)
        except (BudgetExhausted, OutOfScopeError):
            break
        except OSError as exc:
            return unavailable(
                technique, context.asset, f"sampling failed: {exc}", tool="stdlib-http",
            )
        statuses.append(response.status_code)
        headers_seen.update(
            key.lower() for key in response.headers
            if "ratelimit" in key.lower().replace("-", "") or key.lower() == "retry-after"
        )
    if not statuses:
        return unavailable(
            technique, context.asset, "no samples completed", tool="stdlib-http",
        )
    throttled = any(status == 429 for status in statuses)
    observations = [] if (throttled or headers_seen) else [Observation(
        technique, "No rate-limit signalling observed on a read endpoint", "low",
        f"{endpoint.method} {endpoint.path}",
        evidence={"url": url, "samples": len(statuses), "statuses": statuses,
                  "rate_limit_headers": sorted(headers_seen)},
        weakness="missing-rate-limit-signalling",
        recommendation="absence of signalling over a few requests is weak evidence; "
                       "most programs treat rate limiting alone as informational",
    )]
    return executed(
        technique, context.asset, observations, tool="stdlib-http",
        requests_made=len(statuses), started_at=started,
        metadata={"statuses": statuses, "rate_limit_headers": sorted(headers_seen),
                  "throttled": throttled},
    )


__all__ = [
    "ApiSpecification",
    "Endpoint",
    "PRIVILEGED_PROPERTIES",
    "SpecificationError",
    "authorization_matrix",
    "ingest_specification",
    "load_specification",
    "mass_assignment",
    "object_reference_probe",
    "parse_specification",
    "rate_limit_check",
]
