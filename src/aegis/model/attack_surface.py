"""Attack-surface graph (Master Prompt §3 MAP).

A minimal, mergeable model of what the agent has discovered: assets (hosts),
their routes, and parameters. Workers emit surface deltas that the orchestrator
merges into the running graph so later actions can see earlier discoveries.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ParameterLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    PATH = "path"
    COOKIE = "cookie"


class Parameter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    location: ParameterLocation = ParameterLocation.QUERY
    example: str | None = None


class Route(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str = "GET"
    path: str = "/"
    parameters: list[Parameter] = Field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return (self.method.upper(), self.path)


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    kind: str = "api"
    routes: list[Route] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)

    def _merge_in(self, other: Asset) -> None:
        existing = {r.key: r for r in self.routes}
        for route in other.routes:
            if route.key not in existing:
                self.routes.append(route)
                existing[route.key] = route
        for tech in other.technologies:
            if tech not in self.technologies:
                self.technologies.append(tech)


class AttackSurface(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[Asset] = Field(default_factory=list)

    def hosts(self) -> set[str]:
        return {a.host.lower() for a in self.assets}

    def get(self, host: str) -> Asset | None:
        host = host.lower()
        for asset in self.assets:
            if asset.host.lower() == host:
                return asset
        return None

    def merge(self, other: AttackSurface | None) -> AttackSurface:
        """Return a new surface with ``other`` merged in (dedup by host/route)."""
        merged = self.model_copy(deep=True)
        if other is None:
            return merged
        by_host = {a.host.lower(): a for a in merged.assets}
        for asset in other.assets:
            key = asset.host.lower()
            if key in by_host:
                by_host[key]._merge_in(asset)
            else:
                clone = asset.model_copy(deep=True)
                merged.assets.append(clone)
                by_host[key] = clone
        return merged

    @property
    def route_count(self) -> int:
        return sum(len(a.routes) for a in self.assets)
