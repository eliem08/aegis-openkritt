"""Quality, cost, and profit gates for external security benchmarks."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class BenchmarkRun:
    benchmark: str
    detected: int
    reproduced: int
    false_positives: int
    accepted: int = 0
    duplicates: int = 0
    bounty_value: Decimal = Decimal(0)
    model_cost: Decimal = Decimal(0)
    scanner_cost: Decimal = Decimal(0)
    human_review_minutes: float = 0.0
    # Static detector benchmarks may know misses without having any runtime reproduction.
    # This is intentionally last to preserve positional compatibility with older callers.
    missed: int = 0

    def __post_init__(self):
        for name in (
            "detected",
            "reproduced",
            "false_positives",
            "accepted",
            "duplicates",
            "missed",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.reproduced > self.detected:
            raise ValueError("reproduced cannot exceed detected")
        if self.accepted > self.reproduced:
            raise ValueError("accepted cannot exceed reproduced")
        for name in ("bounty_value", "model_cost", "scanner_cost"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.human_review_minutes < 0:
            raise ValueError("human_review_minutes cannot be negative")

    @property
    def detector_precision(self) -> float:
        """Precision of the detector stage only; it does not imply reproduction."""
        denominator = self.detected + self.false_positives
        return self.detected / denominator if denominator else 0.0

    @property
    def detector_recall(self) -> float:
        """Recall of the detector stage when the benchmark supplies labeled misses."""
        denominator = self.detected + self.missed
        return self.detected / denominator if denominator else 0.0

    @property
    def precision(self) -> float:
        """Evidence precision based on findings that reached reproduction."""
        denominator = self.reproduced + self.false_positives
        return self.reproduced / denominator if denominator else 0.0

    @property
    def reproduction_rate(self) -> float:
        return self.reproduced / self.detected if self.detected else 0.0

    @property
    def acceptance_rate(self) -> float:
        return self.accepted / self.reproduced if self.reproduced else 0.0

    @property
    def total_cost(self) -> Decimal:
        return self.model_cost + self.scanner_cost

    @property
    def net_value(self) -> Decimal:
        return self.bounty_value - self.total_cost

    @property
    def duplicate_adjusted_accepts(self) -> int:
        return max(0, self.accepted - self.duplicates)

    @property
    def cost_per_reproduced(self) -> Decimal | None:
        return self.total_cost / self.reproduced if self.reproduced else None


@dataclass(frozen=True)
class ReleaseGate:
    minimum_precision: float = 0.70
    minimum_reproduction_rate: float = 0.20
    maximum_cost_per_reproduced: Decimal = Decimal(250)
    require_nonnegative_net_value: bool = False

    def evaluate(self, run: BenchmarkRun) -> tuple[bool, list[str]]:
        reasons = []
        if run.precision < self.minimum_precision:
            reasons.append("precision_below_threshold")
        if run.reproduction_rate < self.minimum_reproduction_rate:
            reasons.append("reproduction_rate_below_threshold")
        if run.cost_per_reproduced is None:
            reasons.append("no_reproduced_findings")
        elif run.cost_per_reproduced > self.maximum_cost_per_reproduced:
            reasons.append("cost_per_reproduced_above_threshold")
        if self.require_nonnegative_net_value and run.net_value < 0:
            reasons.append("negative_net_value")
        return not reasons, reasons
