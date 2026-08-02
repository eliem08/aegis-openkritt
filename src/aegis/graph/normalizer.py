"""Event → graph normalization (Phase 2 §Normalization and asset graph).

Turns typed :class:`~aegis.adapters.AdapterEvent`s into immutable observations
plus a deduplicated asset view, and is the last in-process place an out-of-scope
or wildcard asset can be stopped before it reaches durable storage:

* **Out-of-scope assets are rejected**, not stored. Scope comes from the signed
  authorization (mirrored by :class:`~aegis.policy.scope.ScopeGuard`); the network
  gateway enforces the same allowlist at request time.
* **Wildcard results are rejected** — a name the resolver flagged as wildcard, or
  a literal ``*.`` entry, never becomes an asset or gets scheduled for probing.
* Anything unparseable is rejected with a reason rather than guessed at.

Rejections are returned, never raised: a single malformed event must not abort a
scan, but it must also never silently become an asset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from aegis.adapters import AdapterEvent, EventKind
from aegis.policy.scope import ScopeGuard

from .model import (
    Asset,
    AssetKind,
    Observation,
    domain_key,
    new_observation,
    normalize_hostname,
    parameter_key,
    route_key,
    service_key,
    technology_key,
    url_key,
)

# Event kinds that carry control/telemetry rather than an asset.
_NON_ASSET_KINDS = {
    EventKind.DIAGNOSTIC, EventKind.PROGRESS, EventKind.TERMINAL,
    EventKind.SECRET_CANDIDATE,  # handled by quarantine + the sensitive-data policy
    EventKind.FINDING,           # handled by the evidence/verification pipeline
}


# Distinct codes so partial coverage and blocks stay visible (Phase 2 §Error handling).
OUT_OF_SCOPE = "out_of_scope"
WILDCARD = "wildcard"
UNPARSEABLE = "unparseable"
UNSUPPORTED = "unsupported_kind"
SENSITIVE = "sensitive_data"     # Phase 4: never store; quarantine + escalate


@dataclass(frozen=True)
class Rejection:
    reason: str
    detail: str
    kind: str


@dataclass
class NormalizationResult:
    observations: list[Observation] = field(default_factory=list)
    assets: dict[str, Asset] = field(default_factory=dict)
    rejections: list[Rejection] = field(default_factory=list)
    sensitive: bool = False                          # a sensitive artifact was hit
    sensitive_classifications: list = field(default_factory=list)  # redacted; never raw

    @property
    def counts(self) -> dict:
        return {
            "observations": len(self.observations),
            "assets": len(self.assets),
            "rejected": len(self.rejections),
        }


@dataclass(frozen=True)
class _Candidate:
    kind: AssetKind
    key: str
    host: str
    data: dict


class Normalizer:
    """Normalizes one task's events into the engagement's asset graph."""

    def __init__(self, *, scope: ScopeGuard, engagement_id: str, scan_id: str, classifier=None) -> None:
        self._scope = scope
        self._engagement_id = engagement_id
        self._scan_id = scan_id
        self._classifier = classifier    # optional sensitive-data ingestion gate

    def normalize(self, events: Iterable[AdapterEvent]) -> NormalizationResult:
        result = NormalizationResult()
        for event in events:
            if event.kind in _NON_ASSET_KINDS:
                continue
            try:
                candidates = self._candidates(event)
            except (ValueError, KeyError, TypeError) as exc:
                result.rejections.append(Rejection(UNPARSEABLE, str(exc), event.kind.value))
                continue
            if not candidates:
                result.rejections.append(
                    Rejection(UNSUPPORTED, f"no asset derived from {event.kind.value}", event.kind.value)
                )
                continue
            for candidate in candidates:
                self._admit(candidate, event, result)
        return result

    # -- internals ----------------------------------------------------------

    def _admit(self, candidate: _Candidate, event: AdapterEvent, result: NormalizationResult) -> None:
        if _is_wildcard(candidate.host, candidate.data):
            result.rejections.append(
                Rejection(WILDCARD, f"wildcard result suppressed: {candidate.host}", candidate.kind.value)
            )
            return
        # Sensitive-data gate (Phase 4): a match is never stored — record only a
        # redacted classification, flag the result, and let the caller quarantine.
        if self._classifier is not None:
            verdict = self._classifier.classify(candidate.data)
            if verdict.sensitive:
                result.sensitive = True
                result.sensitive_classifications.append({
                    "kind": candidate.kind.value, "category": verdict.category.value,
                    "method": verdict.method.value,
                    "markers": sorted({m.redacted for m in verdict.matches}),
                })
                result.rejections.append(
                    Rejection(SENSITIVE, f"sensitive data ({verdict.category.value}) not stored",
                              candidate.kind.value))
                return
        if not self._scope.is_allowed(candidate.host):
            result.rejections.append(
                Rejection(OUT_OF_SCOPE, f"{candidate.host} is not in the authorized scope", candidate.kind.value)
            )
            return

        obs = new_observation(
            engagement_id=self._engagement_id, scan_id=self._scan_id, task_id=event.task_id,
            asset_key=candidate.key, kind=candidate.kind, source=event.source,
            provider=str(event.data.get("provider") or ""), data=candidate.data,
            observed_at=event.observed_at, confidence=event.confidence, raw_ref=event.raw_ref,
        )
        result.observations.append(obs)
        asset = result.assets.get(candidate.key)
        if asset is None:
            asset = Asset(
                engagement_id=self._engagement_id, asset_key=candidate.key, kind=candidate.kind,
                first_seen=obs.observed_at, last_seen=obs.observed_at,
            )
            result.assets[candidate.key] = asset
        asset.merge_observation(obs)

    def _candidates(self, event: AdapterEvent) -> list[_Candidate]:
        data = dict(event.data)
        fallback_host = data.get("host") or event.target

        if event.kind == EventKind.ASSET:
            identifier = data.get("identifier") or data.get("url") or data.get("domain")
            if not identifier:
                raise ValueError("asset event has no identifier")
            asset_type = str(data.get("asset_type") or "").lower()
            if asset_type == "url" or "://" in str(identifier) or "/" in str(identifier):
                return [_Candidate(AssetKind.URL, url_key(identifier), normalize_hostname(identifier), data)]
            host = normalize_hostname(identifier)
            return [_Candidate(AssetKind.DOMAIN, domain_key(host), host, data)]

        if event.kind == EventKind.SERVICE:
            host = normalize_hostname(data.get("host") or fallback_host)
            port = data.get("port")
            if port is None:
                raise ValueError("service event has no port")
            out = [_Candidate(
                AssetKind.SERVICE, service_key(host, port, str(data.get("scheme") or "")), host, data)]
            # A probe reports technologies alongside the service; each is its own asset.
            for tech in data.get("technologies") or []:
                name, _, version = str(tech).partition(":")
                if not name:
                    continue
                out.append(_Candidate(
                    AssetKind.TECHNOLOGY, technology_key(host, name, version), host,
                    {"name": name, "version": version, "host": host},
                ))
            return out

        if event.kind == EventKind.ROUTE:
            host = normalize_hostname(fallback_host)
            path = data.get("path")
            if not path:
                raise ValueError("route event has no path")
            method = str(data.get("method") or "GET")
            rkey = route_key(host, method, str(path))
            out = [_Candidate(AssetKind.ROUTE, rkey, host, data)]
            # A route's parameters are their own assets, hanging off that route.
            for param in data.get("parameters") or []:
                name = param.get("name") if isinstance(param, dict) else param
                if not name:
                    continue
                location = (param.get("location") if isinstance(param, dict) else "") or "query"
                out.append(_Candidate(
                    AssetKind.PARAMETER, parameter_key(rkey, str(name), str(location)), host,
                    {"name": name, "location": location, "route": rkey},
                ))
            return out

        if event.kind == EventKind.PARAMETER:
            host = normalize_hostname(fallback_host)
            name = data.get("name")
            if not name:
                raise ValueError("parameter event has no name")
            location = str(data.get("location") or "query")
            route = data.get("route")
            if not route:
                route = route_key(host, str(data.get("method") or "GET"), str(data.get("path") or "/"))
            return [_Candidate(AssetKind.PARAMETER, parameter_key(str(route), str(name), location), host, data)]

        if event.kind == EventKind.TECHNOLOGY:
            host = normalize_hostname(fallback_host)
            name = data.get("name")
            if not name:
                raise ValueError("technology event has no name")
            version = str(data.get("version") or "")
            return [_Candidate(AssetKind.TECHNOLOGY, technology_key(host, str(name), version), host, data)]

        return []


def _is_wildcard(host: str, data: dict) -> bool:
    """A resolver-flagged wildcard, or a literal wildcard name, is suppressed."""
    if data.get("wildcard") is True:
        return True
    return host.startswith("*.") or host.startswith("*")


def merge_into(existing: dict[str, Asset], incoming: dict[str, Asset]) -> dict[str, Asset]:
    """Fold a batch's assets into a running view, unioning provenance.

    Deduplication across sources happens here: the same natural key seen by two
    adapters yields one asset carrying both sources.
    """
    for key, asset in incoming.items():
        current = existing.get(key)
        if current is None:
            existing[key] = asset
            continue
        current.attributes.update(asset.attributes)
        for source in asset.sources:
            if source not in current.sources:
                current.sources.append(source)
        current.sources.sort()
        current.first_seen = min(current.first_seen, asset.first_seen)
        current.last_seen = max(current.last_seen, asset.last_seen)
        current.observation_count += asset.observation_count
    return existing
