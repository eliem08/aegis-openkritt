"""Map HackerOne hacktivity / disclosed-report JSON to DisclosedReport.

Tolerant of both the GraphQL hacktivity node shape and flatter REST/export
shapes — it reads nested ``weakness`` / ``structured_scope`` / ``team`` objects
when present and falls back to flat keys otherwise. The mapper is pure; fetching
is left to the caller (a corpus export or an authorized API pull), keeping this
free of ToS-sensitive scraping.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .report import DisclosedReport


def _first(*values, default=None):
    for v in values:
        if v not in (None, "", {}):
            return v
    return default


def map_hacktivity_report(node: dict[str, Any]) -> DisclosedReport:
    weakness = node.get("weakness") or {}
    scope = node.get("structured_scope") or {}
    team = node.get("team") or {}

    severity = _first(
        node.get("severity_rating"),
        (node.get("severity") or {}).get("rating") if isinstance(node.get("severity"), dict) else node.get("severity"),
        default=None,
    )

    return DisclosedReport(
        report_id=str(_first(node.get("id"), node.get("databaseId"), node.get("report_id"), default="")),
        source="hackerone",
        program=_first(team.get("handle"), node.get("program"), default="") or "",
        title=node.get("title", "") or "",
        weakness=_first(weakness.get("name"), node.get("weakness_name"), default="") or "",
        cwe=_first(weakness.get("external_id"), node.get("cwe"), default="") or "",
        severity=severity,
        asset_type=_first(scope.get("asset_type"), node.get("asset_type"), default="") or "",
        asset_identifier=_first(scope.get("asset_identifier"), node.get("asset_identifier"), default="") or "",
        substate=node.get("substate", "") or "",
        bounty=_first(node.get("total_awarded_amount"), node.get("bounty"), default=None),
        disclosed_at=_first(node.get("disclosed_at"), node.get("latest_disclosable_activity_at"), default=None),
        url=node.get("url"),
    )


def map_hacktivity(nodes: Iterable[dict]) -> list[DisclosedReport]:
    return [map_hacktivity_report(n) for n in nodes]
