"""Clean-room parameter discovery (Phase 3 §Clean-room parameter discovery).

A from-scratch implementation of the *published operating approach* for finding
hidden request parameters — calibrate, batch, narrow, verify. No AGPL Arjun
source, wordlists, or datasets are used; candidate names come from the caller
(owned/permissive/generated from the authorized asset corpus).

The engine is transport-agnostic: it drives a ``probe(params) -> ProbeResponse``
callable, so the real network path (gateway-enforced, budgeted) lives outside and
the algorithm stays pure and testable. It never widens its capability, refuses
methods/content-types the authorization does not permit, respects request /
candidate / depth / time / anomaly caps, and reports an **unstable** target as an
incomplete diagnostic rather than a clean result.

The operating approach, mirrored from the public description:

1. Capture several control responses; determine which comparison features are
   stable (dynamic content, tokens, and timestamps are disabled).
2. Test bounded batches of candidate names with synthetic marker values.
3. A batch that shifts a stable feature — or reflects a marker — is anomalous.
4. Recursively bisect anomalous batches to isolate the responsible names.
5. Verify each survivor individually with a fresh synthetic value.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Mapping

# Response headers that legitimately change every request; never used for
# stability comparison (calibration would disable them anyway, but excluding them
# up front keeps the stable-feature set meaningful).
VOLATILE_HEADERS = frozenset({
    "date", "set-cookie", "age", "expires", "etag", "last-modified", "x-request-id",
    "x-trace-id", "x-correlation-id", "cf-ray", "x-runtime", "x-timer", "x-amz-cf-id",
    "x-served-by", "x-cache", "content-security-policy-report-only",
})

# Content types this engine understands; a body is encoded per the method.
FORM = "application/x-www-form-urlencoded"
JSON = "application/json"
XML = "application/xml"


@dataclass(frozen=True)
class ProbeResponse:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str = ""
    redirect_location: str = ""


@dataclass(frozen=True)
class ParameterFinding:
    name: str
    reflected: bool
    evidence: str            # "reflection" or the stable feature that shifted
    confidence: float = 1.0


@dataclass
class DiscoveryConfig:
    batch_size: int = 25
    max_requests: int = 600
    max_candidates: int = 4000
    max_depth: int = 8
    calibration_rounds: int = 4
    max_anomalies: int = 40      # more than this => the target echoes everything
    max_seconds: float = 120.0
    min_stable_features: int = 1
    method: str = "GET"
    content_type: str = ""       # "" for GET/query; FORM/JSON/XML otherwise
    permitted_methods: tuple[str, ...] = ("GET",)
    permitted_content_types: tuple[str, ...] = ()


@dataclass
class DiscoveryResult:
    parameters: list[ParameterFinding]
    complete: bool
    reason: str                  # "", unstable_target, request_budget, candidate_cap, ...
    requests: int
    stable_features: list[str]
    baseline: dict = field(default_factory=dict)

    @property
    def names(self) -> list[str]:
        return [p.name for p in self.parameters]


class UnsupportedMethod(ValueError):
    """The requested method/content type is not permitted by the authorization."""


class ParameterDiscovery:
    def __init__(self, probe: Callable[[dict], ProbeResponse],
                 config: DiscoveryConfig | None = None) -> None:
        self._probe_fn = probe
        self.config = config or DiscoveryConfig()
        self._requests = 0
        self._deadline = 0.0
        self._marker_seq = 0
        self._assert_method_permitted()

    # -- public -------------------------------------------------------------

    def discover(self, candidates: list[str]) -> DiscoveryResult:
        cfg = self.config
        self._requests = 0
        self._deadline = time.monotonic() + cfg.max_seconds

        names, truncated = self._prepare(candidates)

        cal = self._calibrate()
        if not cal.stable:
            return self._result([], complete=False, reason="unstable_target",
                                stable=cal.enabled, baseline=cal.baseline)

        survivors: set[str] = set()
        stop_reason = "candidate_cap" if truncated else ""
        for batch in _chunks(names, cfg.batch_size):
            if self._budget_hit():
                stop_reason = self._budget_reason()
                break
            survivors |= self._narrow(batch, cal, depth=0)
            if len(survivors) > cfg.max_anomalies:
                # The target reacts to almost everything — treat as unstable/wildcard.
                return self._result([], complete=False, reason="too_many_anomalies",
                                    stable=cal.enabled, baseline=cal.baseline)

        found = self._verify(sorted(survivors), cal)
        if self._budget_hit() and not stop_reason:
            stop_reason = self._budget_reason()
        return self._result(found, complete=(stop_reason == ""), reason=stop_reason,
                            stable=cal.enabled, baseline=cal.baseline)

    # -- calibration --------------------------------------------------------

    def _calibrate(self) -> "_Calibration":
        """Find features stable across control probes with junk parameters."""
        feature_sets = []
        for i in range(self.config.calibration_rounds):
            marker = self._next_marker()
            resp = self._probe({f"aegis_control_{i}_{marker}": marker})
            feature_sets.append(_features(resp))

        enabled: dict = {}
        for key in feature_sets[0]:
            values = {fs[key] for fs in feature_sets}
            if len(values) == 1:                       # identical across all controls
                enabled[key] = feature_sets[0][key]
        # Status must be stable to compare anything meaningfully; if it is not, or
        # too few features survived, the target is unstable.
        stable = "status" in enabled and len(enabled) >= self.config.min_stable_features
        return _Calibration(enabled=enabled, stable=stable, baseline=dict(enabled))

    # -- narrowing ----------------------------------------------------------

    def _narrow(self, batch: list[str], cal: "_Calibration", *, depth: int) -> set[str]:
        if not batch or self._budget_hit():
            return set()
        markers = {name: self._next_marker() for name in batch}
        resp = self._probe(self._params(markers))

        reflected = {name for name, mk in markers.items() if mk in (resp.body or "")}
        survivors = set(reflected)
        remaining = [n for n in batch if n not in reflected]
        if not remaining:
            return survivors

        # Reflection changes the response on its own, so a batch that had a
        # reflected marker tells us nothing about the rest — re-probe them clean.
        if reflected:
            return survivors | self._narrow(remaining, cal, depth=depth)

        if not self._anomalous(resp, cal):
            return survivors                            # nothing here shifts a feature
        if len(remaining) == 1:
            return survivors | {remaining[0]}
        if depth >= self.config.max_depth:
            return survivors | set(remaining)           # bottomed out; verify individually
        mid = len(remaining) // 2
        return (survivors
                | self._narrow(remaining[:mid], cal, depth=depth + 1)
                | self._narrow(remaining[mid:], cal, depth=depth + 1))

    # -- verification -------------------------------------------------------

    def _verify(self, survivors: list[str], cal: "_Calibration") -> list[ParameterFinding]:
        """Reproduce each survivor individually with a fresh synthetic value."""
        found: list[ParameterFinding] = []
        for name in survivors:
            if self._budget_hit():
                break
            marker = self._next_marker()
            resp = self._probe(self._params({name: marker}))
            if marker in (resp.body or ""):
                found.append(ParameterFinding(name, reflected=True, evidence="reflection"))
                continue
            shifted = self._shifted_feature(resp, cal)
            if shifted is not None:
                found.append(ParameterFinding(name, reflected=False, evidence=shifted))
        return found

    # -- feature comparison -------------------------------------------------

    def _anomalous(self, resp: ProbeResponse, cal: "_Calibration") -> bool:
        return self._shifted_feature(resp, cal) is not None

    @staticmethod
    def _shifted_feature(resp: ProbeResponse, cal: "_Calibration") -> str | None:
        current = _features(resp)
        for key, expected in cal.enabled.items():
            if current.get(key) != expected:
                return key
        return None

    # -- transport + caps ---------------------------------------------------

    def _probe(self, params: dict) -> ProbeResponse:
        self._requests += 1
        return self._probe_fn(params)

    def _params(self, markers: dict) -> dict:
        return dict(markers)

    def _budget_hit(self) -> bool:
        return self._requests >= self.config.max_requests or time.monotonic() >= self._deadline

    def _budget_reason(self) -> str:
        return "time_budget" if time.monotonic() >= self._deadline else "request_budget"

    def _next_marker(self) -> str:
        self._marker_seq += 1
        return f"aegisp{self._marker_seq:05d}zq"

    def _prepare(self, candidates: list[str]) -> tuple[list[str], bool]:
        seen: dict[str, None] = {}
        for name in candidates:
            if name and name not in seen:
                seen[name] = None
        names = list(seen)
        if len(names) > self.config.max_candidates:
            return names[: self.config.max_candidates], True
        return names, False

    def _assert_method_permitted(self) -> None:
        cfg = self.config
        if cfg.method.upper() not in {m.upper() for m in cfg.permitted_methods}:
            raise UnsupportedMethod(f"method {cfg.method!r} not permitted by authorization")
        if cfg.content_type and cfg.content_type not in cfg.permitted_content_types:
            raise UnsupportedMethod(f"content type {cfg.content_type!r} not permitted")

    def _result(self, found, *, complete, reason, stable, baseline) -> DiscoveryResult:
        return DiscoveryResult(
            parameters=found, complete=complete, reason=reason, requests=self._requests,
            stable_features=sorted(stable), baseline=baseline,
        )


@dataclass(frozen=True)
class _Calibration:
    enabled: dict          # stable feature -> baseline value
    stable: bool
    baseline: dict


def _features(resp: ProbeResponse) -> dict:
    body = resp.body or ""
    header_names = tuple(sorted(
        h.lower() for h in (resp.headers or {}) if h.lower() not in VOLATILE_HEADERS
    ))
    return {
        "status": resp.status,
        "redirect": _norm_redirect(resp.redirect_location),
        "headers": header_names,
        "words": len(body.split()),
        "lines": body.count("\n"),
        # Coarse length bucket tolerates tiny per-request jitter; calibration
        # disables it entirely if the body length is not stable.
        "length_bucket": len(body) // 48,
    }


def _norm_redirect(location: str) -> str:
    # Only whether-and-where a redirect points matters, not its query noise.
    return (location or "").split("?", 1)[0].rstrip("/").lower()


def _chunks(items: list[str], size: int):
    for i in range(0, len(items), max(1, size)):
        yield items[i : i + size]
