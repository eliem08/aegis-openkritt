"""Detector orchestration (Phase 3 §Existing detector integration).

Turns the discovered asset graph into *detector tasks* — the transition the
deferred Phase 1 correction called for: recon output plus an operator-owned seed
automatically queues a BOLA task, with no manual wiring.

Three disciplines the spec insists on live here:

* **Targets come from discovery.** Missing-auth, exposed-file, CORS, redirect, and
  error-disclosure detectors receive explicit target sets derived from discovered
  routes. Where there is no route evidence a detector is *skipped* — never falls
  back to scanning hard-coded default paths.
* **BFLA needs a real identity pair.** A BFLA task is planned only for a
  privileged endpoint that names a resolvable low-privilege identity *and* a
  privileged-response discriminator (an explicit signature or an elevated
  identity for a differential). A missing identity is inapplicable, not weak.
* **Each detector reserves and gates its own declared action.** Every task carries
  its detector's action, and :func:`reserve_plan` makes one reservation per
  detector so their budgets are tracked independently.

Candidate creation is not verification (:func:`classify_candidate`): a candidate
becomes verified only with differential evidence or a second independent replay.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.detect.access_control import ObjectRef, ObjectSeed, route_signature

# Mirror of each detector class's declared action (aegis.detect.*).
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
}

# Detectors whose target set is the discovered route set.
ROUTE_TARGET_DETECTORS = ("missing_auth", "exposed_files", "cors", "open_redirect", "error_disclosure")

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
        # route_signature collapses id-like/template segments to '*'.
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
    skipped: dict = field(default_factory=dict)     # detector -> reason

    def by_detector(self, name: str) -> DetectorTask | None:
        return next((t for t in self.tasks if t.detector == name), None)

    @property
    def actions(self) -> list[str]:
        return sorted({t.action for t in self.tasks})

    def has(self, name: str) -> bool:
        return self.by_detector(name) is not None


def routes_from_assets(assets) -> list[Route]:
    """Extract route specs from ROUTE-kind graph assets."""
    from aegis.graph import AssetKind

    routes = []
    for asset in assets:
        if getattr(asset, "kind", None) is not AssetKind.ROUTE:
            continue
        attr = asset.attributes
        routes.append(Route(
            method=str(attr.get("method", "GET")).upper(),
            path=str(attr.get("path", "/")),
            host=str(attr.get("host", "")),
            parameters=tuple(attr.get("parameters", ()) or ()),
        ))
    return routes


def plan_detectors(
    routes: list[Route], *, host: str = "", seeds=(), identities=(), privileged_endpoints=(),
    enabled=None, per_target_requests: int = 2, max_targets_per_detector: int = 200,
    identifier_samples=None,
) -> DetectorPlan:
    """Derive detector tasks from discovered routes + owned seeds + identities.

    ``identifier_samples`` maps a route template to observed object ids; when given,
    a BOLA task is annotated with the id's enumeration risk so a sequential-id IDOR
    is flagged with its true (mass-exposure) impact.
    """
    plan = DetectorPlan()
    enabled = set(enabled) if enabled is not None else set(DETECTOR_ACTIONS)
    names = _names(identities)
    route_paths = _dedupe(r.path for r in routes)
    discovered_sigs = {route_signature(r.path) for r in routes}

    # --- BOLA: recon + owned seed -> concrete object refs (the transition) ---
    if "bola" in enabled:
        if len(names) < 2:
            plan.skipped["bola"] = "needs at least two owned identities"
        else:
            objects = _bola_objects(seeds, discovered_sigs)
            if objects:
                config = {"objects": [{"url": o.url, "owner": o.owner, "canary": o.canary} for o in objects]}
                risk = _enumeration_risk(seeds, identifier_samples)
                if risk is not None:
                    config["enumeration_risk"] = risk.enumeration_risk
                    config["identifier_kind"] = risk.kind.value
                    config["enumerable"] = risk.enumerable
                plan.tasks.append(DetectorTask(
                    "bola", DETECTOR_ACTIONS["bola"], tuple(o.url for o in objects),
                    config, est_requests=len(objects) * len(names),
                ))
            else:
                plan.skipped["bola"] = "no owned seed matched a discovered id-bearing route"

    # --- BFLA: only with a resolvable identity pair + discriminator ---
    if "bfla" in enabled:
        valid = [ep for ep in privileged_endpoints
                 if ep.low_identity in names and ep.has_discriminator
                 and (not ep.elevated_identity or ep.elevated_identity in names)]
        if valid:
            plan.tasks.append(DetectorTask(
                "bfla", DETECTOR_ACTIONS["bfla"], tuple(ep.url for ep in valid),
                {"privileged_endpoints": [
                    {"url": ep.url, "low_identity": ep.low_identity,
                     "elevated_identity": ep.elevated_identity, "signature": ep.signature}
                    for ep in valid]},
                est_requests=len(valid) * 2,
            ))
        elif privileged_endpoints:
            plan.skipped["bfla"] = "no endpoint had a resolvable low identity plus a discriminator"
        else:
            plan.skipped["bfla"] = "no privileged endpoints declared"

    # --- SSRF: only where discovery found a URL-accepting parameter ---
    if "ssrf" in enabled:
        from aegis.active.ssrf import candidate_ssrf_params

        param_names = _dedupe(_param_name(p) for r in routes for p in (r.parameters or []))
        ssrf_params = candidate_ssrf_params([n for n in param_names if n])
        if ssrf_params:
            ssrf_routes = _dedupe(
                r.path for r in routes
                if any(_param_name(p) in ssrf_params for p in (r.parameters or [])))
            plan.tasks.append(DetectorTask(
                "ssrf", DETECTOR_ACTIONS["ssrf"], tuple(ssrf_routes),
                {"parameters": list(ssrf_params)},
                est_requests=len(ssrf_params) * max(1, len(ssrf_routes))))
        else:
            plan.skipped["ssrf"] = "no URL-accepting parameters discovered"

    # --- GraphQL: only where a GraphQL endpoint was discovered ---
    if "graphql" in enabled:
        endpoints = _dedupe(r.path for r in routes if "graphql" in r.path.lower())
        if endpoints:
            plan.tasks.append(DetectorTask(
                "graphql", DETECTOR_ACTIONS["graphql"], tuple(endpoints), {},
                est_requests=len(endpoints) * 3))
        else:
            plan.skipped["graphql"] = "no GraphQL endpoint discovered"

    # --- route-target detectors: explicit targets from discovery only ---
    for detector in ROUTE_TARGET_DETECTORS:
        if detector not in enabled:
            continue
        if not route_paths:
            # No route evidence -> skip, never fall back to hard-coded defaults.
            plan.skipped[detector] = "no discovered routes; hard-coded defaults are not used"
            continue
        targets = tuple(route_paths[:max_targets_per_detector])
        plan.tasks.append(DetectorTask(
            detector, DETECTOR_ACTIONS[detector], targets, {},
            est_requests=len(targets) * per_target_requests,
        ))
    return plan


def reserve_plan(plan: DetectorPlan, reservations, engagement, *, spend_per_request: float = 0.0) -> dict:
    """Reserve each detector task independently under its own declared action.

    Returns ``{detector: (reservation_or_None, action)}``; a ``None`` reservation
    means that detector could not fit under the engagement caps (and is therefore
    blocked without affecting the others).
    """
    out = {}
    for task in plan.tasks:
        reservation = reservations.reserve(
            engagement, spend=task.est_requests * spend_per_request, sessions=1,
            idempotency_key=f"detector:{engagement.id}:{task.detector}",
        )
        out[task.detector] = (reservation, task.action)
    return out


# --- candidate != verification ---------------------------------------------

def is_differential(evidence) -> bool:
    """Differential evidence = at least two independent observations (e.g. a
    privileged baseline and a low-privilege probe, or owner vs. other)."""
    return len(getattr(evidence, "steps", []) or []) >= 2


def classify_candidate(candidate, evidence, *, replay=None) -> str:
    """``"verified"`` only with differential evidence or a confirming second
    independent replay; otherwise ``"hypothesis"`` (fails report gates)."""
    if is_differential(evidence):
        return "verified"
    if replay is not None and replay(candidate):
        return "verified"
    return "hypothesis"


def passes_report_gate(status: str) -> bool:
    return status == "verified"


# --- helpers ---------------------------------------------------------------

def _enumeration_risk(seeds, identifier_samples):
    """Enumeration-risk profile for the seeded objects, if id samples are available."""
    from aegis.active.enumeration import analyze_identifiers

    samples = list(identifier_samples or [])
    if isinstance(identifier_samples, dict):
        samples = [v for values in identifier_samples.values() for v in values]
    # Always include the seed object ids as data points.
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


def _names(identities) -> set:
    out = set()
    for i in identities:
        name = i if isinstance(i, str) else getattr(i, "name", None)
        if name:
            out.add(name)
    return out


def _dedupe(items) -> list:
    seen = {}
    for x in items:
        seen.setdefault(x, None)
    return list(seen)
