"""Deterministic JavaScript and source-map intelligence for authorized artifacts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Mapping
from urllib.parse import urljoin, urlsplit

from ..agentic_os import GraphEdge
from .hunter_techniques import HunterTechnique


class JSDiscoveryKind(str, Enum):
    JS_ROUTE = "js_route"
    API_ENDPOINT = "api_endpoint"
    GRAPHQL_ENDPOINT = "graphql_endpoint"
    WEBSOCKET_ENDPOINT = "websocket_endpoint"
    FEATURE_FLAG = "feature_flag"
    HOST_REFERENCE = "host_reference"
    OAUTH_CLIENT = "oauth_client"
    REDIRECT_URI = "redirect_uri"
    PUBLIC_TRACKING_ID = "public_tracking_identifier"
    SOURCE_MAP = "source_map"
    SOURCE_MODULE = "source_module"


@dataclass(frozen=True)
class JSDiscovery:
    discovery_id: str
    kind: JSDiscoveryKind
    value: str
    source_url: str
    evidence_digest: str
    line: int
    confidence: float
    observed_at: datetime
    technique: HunterTechnique
    authorized: bool
    metadata: Mapping[str, Any] = field(default_factory=dict)


_ABSOLUTE_URL = re.compile(r"(?P<url>(?:https?|wss?)://[^\s'\"<>]+)")
_ROUTE = re.compile(
    r"['\"](?P<route>/(?:api|graphql|oauth|auth|webhooks?|imports?|uploads?|v[0-9]+)"
    r"(?:/[A-Za-z0-9._~!$&'()*+,;=:@%{}-]+)*)['\"]",
    re.IGNORECASE,
)
_SOURCE_MAP = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*(?P<url>[^\s*]+)")
_TRACKING = re.compile(
    r"\b(?P<id>GTM-[A-Z0-9]{5,}|UA-\d{4,}-\d+|G-[A-Z0-9]{6,}|AW-\d{5,})\b",
    re.IGNORECASE,
)
_META_PIXEL = re.compile(
    r"(?:fbq\s*\(\s*['\"]init['\"]\s*,|pixel[_-]?id\s*[:=])\s*['\"]?(?P<id>\d{8,})",
    re.IGNORECASE,
)
_OAUTH_CLIENT = re.compile(
    r"(?:client[_-]?id|oauthClientId)\s*[:=]\s*['\"](?P<value>[A-Za-z0-9._:-]{6,})['\"]",
    re.IGNORECASE,
)
_REDIRECT_URI = re.compile(
    r"(?:redirect[_-]?uri|callbackUrl)\s*[:=]\s*['\"](?P<value>[^'\"]{4,})['\"]",
    re.IGNORECASE,
)
_FEATURE = re.compile(
    r"(?:featureFlags?|features?)\s*[:=]\s*\{(?P<body>[^}]{1,2000})\}",
    re.IGNORECASE | re.DOTALL,
)
_FEATURE_KEY = re.compile(r"['\"]?(?P<key>[A-Za-z][A-Za-z0-9_.-]{2,})['\"]?\s*:")


def _line(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _host_authorized(value: str, scope_hosts: set[str]) -> bool:
    host = (urlsplit(value).hostname or value).lower().rstrip(".")
    return host in scope_hosts or any(
        item.startswith("*.") and host.endswith(item[1:]) for item in scope_hosts
    )


def _stable_id(kind: JSDiscoveryKind, value: str, source: str, digest: str) -> str:
    material = f"{kind.value}\x1f{value}\x1f{source}\x1f{digest}"
    return "jsi:" + sha256(material.encode()).hexdigest()[:24]


class JavaScriptIntelligenceAgent:
    """Extract structured observations; it never fetches URLs or executes JavaScript."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[JSDiscovery, ...]] = {}

    @staticmethod
    def _cache_key(
        bundles: Mapping[str, str], source_maps: Mapping[str, str | Mapping[str, Any]],
        scope_hosts: set[str],
    ) -> str:
        payload = {
            "bundles": sorted((url, sha256(text.encode()).hexdigest())
                              for url, text in bundles.items()),
            "source_maps": sorted((url, sha256(
                (value if isinstance(value, str) else json.dumps(value, sort_keys=True)).encode()
            ).hexdigest()) for url, value in source_maps.items()),
            "scope": sorted(scope_hosts),
        }
        return sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def analyze(
        self,
        bundles: Mapping[str, str],
        *,
        source_maps: Mapping[str, str | Mapping[str, Any]] | None = None,
        scope_hosts: set[str] | None = None,
        observed_at: datetime | None = None,
    ) -> tuple[JSDiscovery, ...]:
        maps = source_maps or {}
        scope = {item.lower().rstrip(".") for item in (scope_hosts or set())}
        key = self._cache_key(bundles, maps, scope)
        if key in self._cache:
            return self._cache[key]
        timestamp = observed_at or datetime.now(UTC)
        discoveries: list[JSDiscovery] = []
        for source_url, text in sorted(bundles.items()):
            discoveries.extend(self._extract(text, source_url, scope, timestamp))
            for match in _SOURCE_MAP.finditer(text):
                map_url = urljoin(source_url, match.group("url").strip())
                discoveries.append(self._item(
                    JSDiscoveryKind.SOURCE_MAP, map_url, source_url, text, match.start(),
                    0.98, timestamp, _host_authorized(map_url, scope),
                    HunterTechnique.JS_SOURCE_MAP_RECOVERY,
                ))
                raw_map = maps.get(map_url) or maps.get(match.group("url").strip())
                if raw_map is not None:
                    discoveries.extend(
                        self._extract_source_map(raw_map, map_url, scope, timestamp)
                    )
        deduped = {
            (item.kind, item.value, item.source_url, item.evidence_digest): item
            for item in discoveries
        }
        result = tuple(sorted(
            deduped.values(), key=lambda item: (item.kind.value, item.value, item.source_url)
        ))
        self._cache[key] = result
        return result

    def _extract(
        self, text: str, source_url: str, scope: set[str], timestamp: datetime,
        *, technique: HunterTechnique = HunterTechnique.JS_ROUTE_RECOVERY,
        metadata: Mapping[str, Any] | None = None,
    ) -> list[JSDiscovery]:
        out: list[JSDiscovery] = []
        for match in _ABSOLUTE_URL.finditer(text):
            value = match.group("url").rstrip("\"'.,);}")
            scheme = urlsplit(value).scheme.lower()
            kind = (
                JSDiscoveryKind.WEBSOCKET_ENDPOINT if scheme in {"ws", "wss"}
                else JSDiscoveryKind.GRAPHQL_ENDPOINT if "graphql" in value.lower()
                else JSDiscoveryKind.API_ENDPOINT if "/api" in value.lower()
                else JSDiscoveryKind.HOST_REFERENCE
            )
            out.append(self._item(
                kind, value, source_url, text, match.start(), 0.92, timestamp,
                _host_authorized(value, scope), technique, metadata,
            ))
        for match in _ROUTE.finditer(text):
            route = match.group("route")
            kind = (
                JSDiscoveryKind.GRAPHQL_ENDPOINT if "graphql" in route.lower()
                else JSDiscoveryKind.API_ENDPOINT if route.lower().startswith(("/api", "/v"))
                else JSDiscoveryKind.JS_ROUTE
            )
            out.append(self._item(
                kind, route, source_url, text, match.start(), 0.84, timestamp,
                _host_authorized(source_url, scope), technique, metadata,
            ))
        for regex, kind, confidence in (
            (_TRACKING, JSDiscoveryKind.PUBLIC_TRACKING_ID, 0.96),
            (_META_PIXEL, JSDiscoveryKind.PUBLIC_TRACKING_ID, 0.92),
            (_OAUTH_CLIENT, JSDiscoveryKind.OAUTH_CLIENT, 0.88),
            (_REDIRECT_URI, JSDiscoveryKind.REDIRECT_URI, 0.86),
        ):
            for match in regex.finditer(text):
                value = match.groupdict().get("id") or match.groupdict().get("value") or ""
                out.append(self._item(
                    kind, value, source_url, text, match.start(), confidence, timestamp,
                    _host_authorized(source_url, scope), technique, metadata,
                ))
        for container in _FEATURE.finditer(text):
            for match in _FEATURE_KEY.finditer(container.group("body")):
                out.append(self._item(
                    JSDiscoveryKind.FEATURE_FLAG, match.group("key"), source_url, text,
                    container.start() + match.start(), 0.72, timestamp,
                    _host_authorized(source_url, scope), technique, metadata,
                ))
        return out

    def _extract_source_map(
        self, raw: str | Mapping[str, Any], map_url: str, scope: set[str], timestamp: datetime,
    ) -> list[JSDiscovery]:
        try:
            data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return []
        digest = sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()
        sources = data.get("sources") if isinstance(data.get("sources"), list) else []
        contents = data.get("sourcesContent") if isinstance(data.get("sourcesContent"), list) else []
        out: list[JSDiscovery] = []
        for index, source in enumerate(sources[:500]):
            name = str(source)[:1000]
            out.append(JSDiscovery(
                _stable_id(JSDiscoveryKind.SOURCE_MODULE, name, map_url, digest),
                JSDiscoveryKind.SOURCE_MODULE, name, map_url, digest, 1, 0.99, timestamp,
                HunterTechnique.JS_SOURCE_MAP_RECOVERY,
                _host_authorized(map_url, scope), {"source_map_digest": digest},
            ))
            if index < len(contents) and isinstance(contents[index], str):
                out.extend(self._extract(
                    contents[index], f"{map_url}#{name}", scope, timestamp,
                    technique=HunterTechnique.JS_SOURCE_MAP_RECOVERY,
                    metadata={"source_map_digest": digest, "original_filename": name},
                ))
        return out

    @staticmethod
    def _item(
        kind: JSDiscoveryKind, value: str, source_url: str, text: str, position: int,
        confidence: float, timestamp: datetime, authorized: bool,
        technique: HunterTechnique, metadata: Mapping[str, Any] | None = None,
    ) -> JSDiscovery:
        digest = sha256(text.encode()).hexdigest()
        return JSDiscovery(
            _stable_id(kind, value, source_url, digest), kind, value, source_url, digest,
            _line(text, position), confidence, timestamp, technique, authorized,
            dict(metadata or {}),
        )

    @staticmethod
    def persist(discoveries: tuple[JSDiscovery, ...], graph) -> None:
        for item in discoveries:
            source_id = "js:" + sha256(item.source_url.encode()).hexdigest()[:20]
            graph.upsert_node(
                source_id, "javascript_artifact", locator=item.source_url,
                evidence_digest=item.evidence_digest, observed_at=item.observed_at.isoformat(),
                authorized=item.authorized,
            )
            graph.upsert_node(
                item.discovery_id, item.kind.value, value=item.value,
                observed_at=item.observed_at.isoformat(), authorized=item.authorized,
                technique=item.technique.value, line=item.line, **dict(item.metadata),
            )
            graph.connect(GraphEdge(
                source_id, "reveals", item.discovery_id,
                f"{item.source_url}:{item.line}:{item.evidence_digest}", item.confidence,
            ))


__all__ = ["JSDiscovery", "JSDiscoveryKind", "JavaScriptIntelligenceAgent"]
