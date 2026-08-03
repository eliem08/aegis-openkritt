"""Automatic, scope-gated, profit-aware bug-bounty hunting loop.

Each cycle performs three bounded passes: discover authorized repositories, allocate
analysis using explainable expected value plus exploration, then launch only the
selected verification work. It never exploits or submits, and dry-run is the
default.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from decimal import Decimal

from aegis.integrations.repo_pipeline import console_for_scans, run_repo_pipeline
from aegis.learn import Calibration, sync_hackerone_outcomes
from aegis.report import build_console

from .portfolio import PortfolioDecision, plan_portfolio


@dataclass
class HuntConfig:
    model: str = ""
    fallback_models: tuple[str, ...] = ()
    only_handles: tuple[str, ...] = ()
    max_programs: int = 3
    max_repos_per_program: int = 3
    interval_seconds: float = 3600.0
    dry_run: bool = True
    inspect_limit: int = 20
    require_bounty: bool = True
    workflow_id: str = ""
    post_script_id: str = ""
    portfolio_capacity: int = 0  # zero means all repositories surviving discovery caps
    exploration_fraction: float = 0.2
    expected_bounties: dict[str, Decimal] = field(default_factory=dict)
    base_valid_probability: float = 0.5
    base_acceptance_probability: float = 0.5
    estimated_model_cost: Decimal = Decimal("0.02")
    estimated_scanner_cost: Decimal = Decimal("0.05")
    estimated_verification_time_cost: Decimal = Decimal("0.50")

    def __post_init__(self) -> None:
        if self.max_programs < 0 or self.max_repos_per_program < 0 or self.portfolio_capacity < 0:
            raise ValueError("hunt capacities cannot be negative")
        if not 0 <= self.exploration_fraction <= 1:
            raise ValueError("exploration_fraction must be in [0, 1]")
        if not 0 <= self.base_valid_probability <= 1:
            raise ValueError("base_valid_probability must be in [0, 1]")
        if not 0 <= self.base_acceptance_probability <= 1:
            raise ValueError("base_acceptance_probability must be in [0, 1]")
        for value in (
            self.estimated_model_cost,
            self.estimated_scanner_cost,
            self.estimated_verification_time_cost,
        ):
            if value < 0:
                raise ValueError("estimated hunting costs cannot be negative")
        normalized = {}
        for handle, amount in self.expected_bounties.items():
            name = str(handle).strip()
            try:
                value = Decimal(str(amount))
            except Exception as exc:
                raise ValueError(f"invalid expected bounty for {name or 'empty handle'}") from exc
            if not name or value < 0:
                raise ValueError("expected bounty handles must be non-empty and amounts non-negative")
            normalized[name] = value

        self.expected_bounties = normalized

@dataclass
class HuntReport:
    dry_run: bool = True
    programs: list = field(default_factory=list)
    launched_scans: list = field(default_factory=list)
    console: dict = field(default_factory=dict)
    sync: object = None
    selected: list = field(default_factory=list)
    portfolio: list[PortfolioDecision] = field(default_factory=list)

    def summary(self) -> dict:
        launched = sum(len([launch for launch in p.launches if launch.ok]) for p in self.programs)
        gated = [p.handle for p in self.programs if p.gated]
        launch_errors = [
            launch.error for p in self.programs for launch in p.launches if launch.error
        ][:5]
        chosen = [decision for decision in self.portfolio if decision.selected]
        estimated_cost = sum((d.score.total_cost for d in chosen), Decimal(0))
        expected_net = sum((d.score.net_expected_value for d in chosen), Decimal(0))
        return {
            "dry_run": self.dry_run,
            "passes": ["discovery", "portfolio_allocation", "verification"],
            "auto_selected": [
                {
                    "handle": candidate.handle,
                    "bounty_repos": candidate.repo_count,
                    "top_severity": candidate.top_severity,
                    "profitability": candidate.profitability,
                }
                for candidate in self.selected
            ],
            "programs_considered": len(self.programs),
            "programs_gated_out": gated,
            "repos_in_scope": sum(len(p.repos) for p in self.programs),
            "portfolio_selected": len(chosen),
            "portfolio_skipped": len(self.portfolio) - len(chosen),
            "estimated_selected_cost_usd": str(estimated_cost),
            "expected_selected_net_value_usd": str(expected_net),
            "selected_missing_bounty": sum(d.score.missing_bounty for d in chosen),
            "portfolio": [decision.summary() for decision in self.portfolio],
            "scans_launched_this_cycle": launched,
            "launch_errors": launch_errors,
            "scans_tracked": len(self.launched_scans),
            "findings": (self.console or {}).get("totals", {}).get("candidates", 0),
            "outcomes_synced": getattr(self.sync, "recorded", 0),
        }


class HuntOrchestrator:
    def __init__(self, h1_client, ok_client, outcomes, ledger, *, config: HuntConfig):
        self._h1 = h1_client
        self._ok = ok_client
        self._outcomes = outcomes
        self._ledger = ledger
        self._cfg = config
        self._tracked: set[str] = set()
        self._selected: list = []

    def _handles(self) -> list[str]:
        if self._cfg.only_handles:
            self._selected = []
            return list(self._cfg.only_handles)
        from .selector import select_programs

        self._selected = select_programs(
            self._h1,
            want=self._cfg.max_programs,
            inspect_limit=self._cfg.inspect_limit,
            require_bounty=self._cfg.require_bounty,
        )
        return [candidate.handle for candidate in self._selected]

    def _discover(self) -> list:
        cfg = self._cfg
        return [
            run_repo_pipeline(
                self._h1,
                self._ok,
                handle,
                model=cfg.model,
                fallbacks=(cfg.fallback_models or None),
                bounty_only=cfg.require_bounty,
                workflow_id=(cfg.workflow_id or None),
                post_script_id=(cfg.post_script_id or None),
                launch=False,
                max_repos=cfg.max_repos_per_program,
            )
            for handle in self._handles()[: cfg.max_programs]
        ]

    def cycle(self) -> HuntReport:
        cfg = self._cfg
        calibration = Calibration.from_outcomes(self._outcomes.all())

        # Pass 1: authorized, inexpensive scope discovery only.
        programs = self._discover()
        discovered_count = sum(len(program.repos) for program in programs)
        capacity = cfg.portfolio_capacity or discovered_count

        # Pass 2: explainable expected-value allocation with bounded exploration.
        portfolio = plan_portfolio(
            programs,
            capacity=capacity,
            expected_bounties=cfg.expected_bounties,
            p_valid=cfg.base_valid_probability,
            p_accepted=cfg.base_acceptance_probability,
            model_cost=cfg.estimated_model_cost,
            scanner_cost=cfg.estimated_scanner_cost,
            verification_time_cost=cfg.estimated_verification_time_cost,
            exploration_fraction=cfg.exploration_fraction,
        )
        selected_by_handle: dict[str, set[str]] = {}
        for decision in portfolio:
            if decision.selected:
                selected_by_handle.setdefault(decision.handle, set()).add(decision.repo_full)

        # Pass 3: launch only selected repositories, and only when explicitly armed.
        if not cfg.dry_run:
            for program in programs:
                allowlist = selected_by_handle.get(program.handle, set())
                if program.gated or not allowlist:
                    continue
                launched = run_repo_pipeline(
                    self._h1,
                    self._ok,
                    program.handle,
                    model=cfg.model,
                    fallbacks=(cfg.fallback_models or None),
                    bounty_only=cfg.require_bounty,
                    workflow_id=(cfg.workflow_id or None),
                    post_script_id=(cfg.post_script_id or None),
                    launch=True,
                    repo_allowlist=allowlist,
                )
                program.launches = launched.launches
                for launch in program.launches:
                    if launch.scan_id:
                        self._tracked.add(launch.scan_id)

        console = (
            console_for_scans(self._ok, sorted(self._tracked), calibration=calibration)
            if self._tracked
            else build_console([], calibration=calibration)
        )
        sync = sync_hackerone_outcomes(self._h1, self._ledger, self._outcomes)

        return HuntReport(
            dry_run=cfg.dry_run,
            programs=programs,
            launched_scans=sorted(self._tracked),
            console=console,
            sync=sync,
            selected=list(self._selected),
            portfolio=portfolio,
        )

    def run(self, *, cycles: int | None = None, sleep=time.sleep):
        """Yield one report per cycle, sleeping between cycles when requested."""
        count = 0
        while cycles is None or count < cycles:
            yield self.cycle()
            count += 1
            if cycles is not None and count >= cycles:
                break
            sleep(self._cfg.interval_seconds)
