"""End-to-end web-lane runner: recon -> probe -> crawl -> detect -> OAST, assembled.

Aegis already has the adapters (subfinder, httpx, katana, gau, jsluice, nuclei, dalfox)
and OAST. This is the missing piece — a single guarded pipeline that sequences them and
collects validated findings, the web-lane equivalent of the code lane's hunt loop.

Boundary, non-negotiable and enforced here: the web lane actively probes LIVE hosts, so
it runs ONLY against a scope the operator has explicitly authorized, and refuses any
host outside that scope. Aegis assembles and drives the stages; the operator authorizes
the target and supplies the executing adapters. Aegis never probes a third-party system
on its own initiative — the same line the reproduction agent holds for local targets.

Stages are injected (each a callable), so the pipeline is testable offline and the
operator wires the real adapters against their authorized scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


class ScopeError(RuntimeError):
    """The run was refused: no authorization, or a host outside the authorized scope."""


@dataclass
class WebScope:
    """What the operator is authorized to test. ``authorized`` must be set explicitly —
    an unset scope refuses to run. ``hosts`` is the allowlist the pipeline is confined to."""
    seed: str                        # the root domain/host the operator owns/authorized
    hosts: frozenset = field(default_factory=frozenset)   # explicit allowlist (in-scope)
    authorized: bool = False         # the operator asserts they may test this scope
    respect_no_scan: bool = True     # honor programs that forbid scanning (operator sets)

    def permits(self, host: str) -> bool:
        h = (host or "").lower().split(":")[0]
        if not h:
            return False
        if h == self.seed.lower() or h in {x.lower() for x in self.hosts}:
            return True
        # subdomains of the seed are in scope unless an allowlist is given
        return not self.hosts and h.endswith("." + self.seed.lower())


@dataclass
class WebLaneResult:
    scope: str
    subdomains: list[str] = field(default_factory=list)
    live: list[dict] = field(default_factory=list)        # probed live endpoints
    endpoints: list[str] = field(default_factory=list)     # crawled/passive URLs
    findings: list[dict] = field(default_factory=list)     # detector/nuclei/dalfox findings
    oast_hits: list[dict] = field(default_factory=list)
    stages_run: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"scope": self.scope, "subdomains": len(self.subdomains),
                "live": len(self.live), "endpoints": len(self.endpoints),
                "findings": len(self.findings), "oast_hits": len(self.oast_hits),
                "stages_run": self.stages_run, "notes": self.notes}


# A stage is: callable(scope, result) -> None (it mutates result). Injected by the caller.
Stage = Callable[[WebScope, WebLaneResult], None]


class WebLaneRunner:
    """Sequence the web-lane stages against an AUTHORIZED scope, confined to its hosts."""

    #: canonical order; a caller supplies the stages it wants, keyed by these names.
    ORDER = ("recon", "probe", "crawl", "passive", "js", "detect", "oast")

    def __init__(self, stages: dict[str, Stage], *, on_event: Callable[[str, dict], None] | None = None):
        self._stages = stages
        self._on_event = on_event or (lambda *_: None)

    def run(self, scope: WebScope) -> WebLaneResult:
        if not scope.authorized:
            raise ScopeError(
                "web-lane run refused: scope.authorized is False. The web lane actively "
                "probes live hosts — only run it against a target you are authorized to "
                "test, under the program's scanning rules."
            )
        if not scope.seed:
            raise ScopeError("web-lane run refused: no seed host in scope")
        result = WebLaneResult(scope=scope.seed)
        for name in self.ORDER:
            stage = self._stages.get(name)
            if stage is None:
                continue
            self._on_event("stage_start", {"stage": name})
            try:
                stage(scope, result)
            except Exception as exc:
                result.notes.append(f"{name}: {type(exc).__name__}: {exc}"[:200])
                self._on_event("stage_error", {"stage": name, "error": str(exc)[:120]})
                continue
            result.stages_run.append(name)
            self._on_event("stage_done", {"stage": name})
        # confine every discovered host to the authorized scope (defence in depth)
        result.subdomains = [h for h in result.subdomains if scope.permits(h)]
        result.findings = [f for f in result.findings
                           if scope.permits(_host_of(f.get("url") or f.get("host") or scope.seed))]
        self._on_event("completed", result.summary())
        return result


def _host_of(url_or_host: str) -> str:
    from urllib.parse import urlsplit
    s = str(url_or_host or "")
    return (urlsplit(s).hostname or s.split("/")[0]) if s else ""
