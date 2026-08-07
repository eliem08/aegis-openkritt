"""Coverage intelligence: identify high-value surfaces nobody has checked."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CoverageCell:
    surface: str
    weakness: str
    attempts: int
    last_result: str = ""
    changed_since_last_attempt: bool = False
    expected_value_usd: float = 0.0


def blind_spot_score(cell: CoverageCell) -> float:
    freshness = 1.0 if cell.changed_since_last_attempt else 0.0
    unexplored = 1.0 / (cell.attempts + 1.0)
    value = max(0.0, cell.expected_value_usd) / 1000.0
    return 2.0 * unexplored + 1.5 * freshness + min(value, 5.0)


def prioritize_blind_spots(cells: list[CoverageCell]) -> tuple[CoverageCell, ...]:
    return tuple(
        sorted(
            cells,
            key=lambda cell: (
                blind_spot_score(cell),
                cell.expected_value_usd,
                cell.surface,
                cell.weakness,
            ),
            reverse=True,
        )
    )
