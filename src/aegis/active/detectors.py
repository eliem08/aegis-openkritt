"""Detector orchestration (Phase 3 §Existing detector integration).

Turns the discovered asset graph into *detector tasks* — the transition the
deferred Phase 1 correction called for: recon output plus an operator-owned seed
automatically queues a BOLA task, with no manual wiring.

Candidate creation is not verification (:func:`classify_candidate`): a candidate
becomes verified only with differential evidence or a second independent replay.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.detect.access_control import ObjectRef, ObjectSeed, route_signature

DETECTOR_ACTIONS = {
    "bola": "authenticated_testing",
    "bfla": "authenticated_testing",
    "cross_tenant": "authenticated_testing",
    "missing_auth": "authenticated_testing",
    "exposed_files": "passive_discovery",
    "error_disclosure": "benign_request_mutation",
    "cors": "benign_request_mutation",
    "open_redirect": "benign_request_mutation",
    "ssrf": "benign_request_mutation",
    "graphql": "benign_request_mutation",
    "path_bypass": "benign_request_mutation",
    "http_desync": "benign_request_mutation",
    "contract_review": "passive_discovery",
}

ROUTE_TARGET_DETECTORS = (
    "missing_auth",
    "exposed_files",
    "cors",
    "open_redirect",
    "error_disclosure",
)

Seed = ObjectSeed


@dataclass(frozen=True)
class BflaEndpoint:
    url: str
    low_identity: str
    elevated_identity: str = ""
    signature: str = ""

    @property
    def has_discriminator(self) -> bool:
        return bool(self.signature) or bool(self.elevated_identity)


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    host: str = ""
    parameters: tuple = ()

    @property
    def id_bearing(self) -> bool:
        return "*" in route_signature(self.path).split("/")


@dataclass(frozen=True)
class DetectorTask:
    detector: str
    action: str
    targets: tuple[str, ...]
    config: dict = field(default_factory=dict)
    est_requests: int = 0


@dataclass
class DetectorPlan:
    tasks: list[DetectorTask] = field(default_factory=list)
    skipped: dict = field(default_factory=dict)

    def by_detector(self, name: str) -> DetectorTask | None:
        return next((t for t in self.tasks if t.detector == name), None)

    @property
    def actions(self) -> list[str]:
        return sorted({t.action for t in self.tasks})

    def has(self, name: str) -> bool:
        return self.by_detector(name) is not None


def routes_from_assets(assets) -> list[Route]:
    from aegis.graph import AssetKind

    routes = []
    for asset in assets:
        if getattr(asset, "kind", None) is not AssetKind.ROUTE:
            continue
        attr = asset.attributes
        routes.append(
            Route(
                method=str(attr.get("method", "GET")).upper(),
                path=str(attr.get("path", "/")),
                host=str(attr.get("host", "")),
                parameters=tuple(attr.get("parameters", ()) or ()),
            )
        )
    return routes


def plan_detectors(
    routes: list[Route],
    *,
    host: str = "",
    seeds=(),
    identities=(),
    privileged_endpoints=(),
    enabled=None,
    per_target_requests: int = 2,
    max_targets_per_detector: int = 200,
    identifier_samples=None,
    contracts=(),
    desync_candidates=(),
) -> DetectorPlan:
    """Derive detector tasks from discovered routes and supplied evidence.

    ``desync_candidates`` are evidence-derived hypotheses from
    :func:`aegis.active.http_desync.analyze_desync_observations`.  They never create routes:
    only candidates whose route was already discovered may become an ``http_desync`` task.
    """
    plan = DetectorPlan()
    enabled = set(enabled) if enabled is not None else set(DETECTOR_ACTIONS)
    names = _names(identities)
    route_paths = _dedupe(r.path for r in routes)
    discovered_sigs = {route_signature(r.path) for r in routes}

    if "bola" in enabled:
        if len(names) < 2:
            plan.skipped["bola"] = "needs at least two owned identities"
        else:
            objects = _bola_objects(seeds, discovered_sigs)
            if objects:
                config = {
                    "objects": [
                        {"url": o.url, "owner": o.owner, "canary": o.canary} for o in objects
                    ]
                }
                risk = _enumeration_risk(seeds, identifier_samples)
                if risk is not None:
                    config["enumeration_risk"] = risk.enumeration_risk
                    config["identifier_kind"] = risk.kind.value
                    config["enumerable"] = risk.enumerable
                plan.tasks.append(
                    DetectorTask(
                        "bola",
                        DETECTOR_ACTIONS["bola"],
                        tuple(o.url for o in objects),
                        config,
                        est_requests=len(objects) * len(names),
                    )
                )
            else:
                plan.skipped["bola"] = "no owned seed matched a discovered id-bearing route"

    if "bfla" in enabled:
        valid = [
            ep
            for ep in privileged_endpoints
            if ep.low_identity in names
            and ep.has_discriminator
            and (not ep.elevated_identity or ep.elevated_identity in names)
        ]
        if valid:
            plan.tasks.append(
                DetectorTask(
                    "bfla",
                    DETECTOR_ACTIONS["bfla"],
                    tuple(ep.url for ep in valid),
                    {
                        "privileged_endpoints": [
                            {
                                "url": ep.url,
                                "low_identity": ep.low_identity,
                                "elevated_identity": ep.elevated_identity,
                                "signature": ep.signature,
                            }
                            for ep in valid
                        ]
                    },
                    est_requests=len(valid) * 2,
                )
            )
        elif privileged_endpoints:
            plan.skipped["bfla"] = "no endpoint had a resolvable low identity plus a discriminator"
        else:
            plan.skipped["bfla"] = "no privileged endpoints declared"

    if "ssrf" in enabled:
        from aegis.active.ssrf import candidate_ssrf_params

        param_names = _dedupe(_param_name(p) for r in routes for p in (r.parameters or []))
        ssrf_params = candidate_ssrf_params([n for n in param_names if n])
        if ssrf_params:
            ssrf_routes = _dedupe(
                r.path
                for r in routes
                if any(_param_name(p) in ssrf_params for p in (r.parameters or []))
            )
            plan.tasks.append(
                DetectorTask(
                    "ssrf",
                    DETECTOR_ACTIONS["ssrf"],
                    tuple(ssrf_routes),
                    {"parameters": list(ssrf_params)},
                    est_requests=len(ssrf_params) * max(1, len(ssrf_routes)),
                )
            )
        else:
            plan.skipped["ssrf"] = "no URL-accepting parameters discovered"

    if "graphql" in enabled:
        endpoints = _dedupe(r.path for r in routes if "graphql" in r.path.lower())
        if endpoints:
            plan.tasks.append(
                DetectorTask(
                    "graphql",
                    DETECTOR_ACTIONS["graphql"],
                    tuple(endpoints),
                    {},
                    est_requests=len(endpoints) * 3,
                )
            )
        else:
            plan.skipped["graphql"] = "no GraphQL endpoint discovered"

    if "http_desync" in enabled:
        discovered = set(route_paths)
        eligible = [candidate for candidate in desync_candidates if candidate.route in discovered]
        if eligible:
            targets = tuple(dict.fromkeys(candidate.route for candidate in eligible))
            plan.tasks.append(
                DetectorTask(
                    "http_desync",
                    DETECTOR_ACTIONS["http_desync"],
                    targets[:max_targets_per_detector],
                    {
                        "hypotheses": [
                            {
                                "route": candidate.route,
                                "host": candidate.host,
                                "family": candidate.family.value,
                                "confidence": candidate.confidence,
                                "rationale": candidate.rationale,
                                "evidence_count": candidate.evidence_count,
                            }
                            for candidate in eligible[:max_targets_per_detector]
                        ],
                        "mode": "evidence_guided_validation",
                    },
                    est_requests=min(
                        len(targets), max_targets_per_detector
                    ) * max(2, per_target_requests),
                )
            )
        elif desync_candidates:
            plan.skipped["http_desync"] = "desync evidence did not match a discovered route"
        else:
            plan.skipped["http_desync"] = "no HTTP desync evidence candidates supplied"

    if "contract_review" in enabled and contracts:
        named = [(_contract_name(c, i), _contract_source(c)) for i, c in enumerate(contracts)]
        analyzable = [(name, src) for name, src in named if src]
        if analyzable:
            plan.tasks.append(
                DetectorTask(
                    "contract_review",
                    DETECTOR_ACTIONS["contract_review"],
                    tuple(name for name, _ in analyzable),
                    {"contracts": len(analyzable)},
                    est_requests=0,
                )
            )
        else:
            plan.skipped["contract_review"] = "no contract source provided"

    for detector in ROUTE_TARGET_DETECTORS:
        if detector not in enabled:
            continue
        if not route_paths:
            plan.skipped[detector] = "no discovered routes; hard-coded defaults are not used"
            continue
        targets = tuple(route_paths[:max_targets_per_detector])
        plan.tasks.append(
            DetectorTask(
                detector,
                DETECTOR_ACTIONS[detector],
                targets,
                {},
                est_requests=len(targets) * per_target_requests,
            )
        )
    return plan


def reserve_plan(plan: DetectorPlan, reservations, engagement, *, spend_per_request: float = 0.0) -> dict:
    out = {}
    for task in plan.tasks:
        reservation = reservations.reserve(
            engagement,
            spend=task.est_requests * spend_per_request,
            sessions=1,
            idempotency_key=f"detector:{engagement.id}:{task.detector}",
        )
        out[task.detector] = (reservation, task.action)
    return out


def is_differential(evidence) -> bool:
    return len(getattr(evidence, "steps", []) or []) >= 2


def classify_candidate(candidate, evidence, *, replay=None) -> str:
    if is_differential(evidence):
        return "verified"
    if replay is not None and replay(candidate):
        return "verified"
    return "hypothesis"


def passes_report_gate(status: str) -> bool:
    return status == "verified"


def _enumeration_risk(seeds, identifier_samples):
    from aegis.active.enumeration import analyze_identifiers

    samples = list(identifier_samples or [])
    if isinstance(identifier_samples, dict):
        samples = [v for values in identifier_samples.values() for v in values]
    samples = samples + [str(s.object_id) for s in seeds]
    samples = [s for s in samples if s]
    return analyze_identifiers(samples) if samples else None


def _bola_objects(seeds, discovered_sigs) -> list[ObjectRef]:
    objects = []
    for seed in seeds:
        if route_signature(seed.route) not in discovered_sigs:
            continue
        if "{" in seed.route:
            url = seed.route.replace("{" + seed.param + "}", str(seed.object_id))
        else:
            url = seed.route
        objects.append(ObjectRef(url=url, owner=seed.owner, canary=seed.canary))
    return objects


def _param_name(param) -> str:
    return str(param.get("name") if isinstance(param, dict) else param or "")


def _contract_name(contract, index: int) -> str:
    if isinstance(contract, dict):
        return str(contract.get("name") or contract.get("path") or f"contract-{index}")
    return str(
        getattr(contract, "name", None)
        or getattr(contract, "path", None)
        or f"contract-{index}"
    )


def _contract_source(contract) -> str:
    if isinstance(contract, dict):
        return str(contract.get("source") or contract.get("text") or "")
    return str(getattr(contract, "source", None) or getattr(contract, "text", None) or "")


def _names(identities) -> set:
    out = set()
    for identity in identities:
        name = identity if isinstance(identity, str) else getattr(identity, "name", None)
        if name:
            out.add(name)
    return out


def _dedupe(items) -> list:
    seen = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)
