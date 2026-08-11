"""Deterministic JSON and Markdown effectiveness reporting."""

from __future__ import annotations

import json
from dataclasses import asdict
from decimal import Decimal
from enum import Enum

from .metrics import EffectivenessMetrics, MetricRow, rows_for
from .models import canonical_document


def _json_value(value):
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


def row_document(row: MetricRow) -> dict:
    return _json_value(asdict(row))


def report_document(metrics: EffectivenessMetrics, *, authoritative: bool) -> dict:
    return {
        "schema_version": 1,
        "authoritative": authoritative,
        "overall": row_document(metrics.overall),
        "groups": {
            name: [row_document(row) for row in values]
            for name, values in rows_for(metrics)
        },
    }


def render_json(metrics: EffectivenessMetrics, *, authoritative: bool) -> str:
    return json.dumps(report_document(metrics, authoritative=authoritative), indent=2, sort_keys=True)


def render_v2_json(document: dict) -> str:
    return json.dumps(canonical_document(document), indent=2, sort_keys=True)


def render_v2_markdown(document: dict) -> str:
    economics = document["economics"]
    profile = document["profiles"]["overall"]
    lines = [
        "# Aegis Profitability Acceleration V2", "",
        f"Authoritative production data: **{'yes' if document['authoritative'] else 'no'}**",
        f"Model: `{document['model_version']}`", "", "## Funnel", "",
        "| Opportunities | Candidates | Reproduced | Verified | Approved | Submitted | Accepted | Duplicates |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {profile['opportunities']} | {profile['candidates']} | {profile['reproduced']} | "
        f"{profile['independently_verified']} | {profile['human_approved']} | "
        f"{profile['submitted']} | {profile['accepted']} | {profile['duplicates']} |",
        "", "## Economics", "",
        f"- Status: `{economics['state'].value}`",
        f"- Realized profit excluding human cost: {_money_or_unknown(economics['realized_profit_excluding_human_cost_usd'])}",
        f"- Realized profit including human cost: {_money_or_unknown(economics['realized_profit_usd'])}",
        f"- Missing inputs: {', '.join(economics['missing_inputs']) or 'none'}", "",
        f"Human review queue: **{len(document['review_queue'])}**", "",
        "Learned rankings remain shadow-only. Human submission remains mandatory.", "",
    ]
    return "\n".join(lines)


def render_markdown(metrics: EffectivenessMetrics, *, authoritative: bool) -> str:
    overall = metrics.overall
    lines = [
        "# Aegis Hunter Effectiveness",
        "",
        f"Authoritative production data: **{'yes' if authoritative else 'no'}**",
        "",
        "## Overall",
        "",
        "| Opportunities | Reproduced | Approved | Submitted | Accepted | Duplicates | "
        "Known bounty | Recorded cost | Realized profit |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {overall.opportunities} | {overall.reproduced} | {overall.human_approved} | "
        f"{overall.submitted} | {overall.accepted} | {overall.duplicates} | "
        f"${overall.known_bounty_usd} | ${overall.total_recorded_cost_usd} | "
        f"{_money_or_unknown(overall.realized_profit_usd)} |",
    ]
    for name, values in rows_for(metrics):
        lines.extend(["", f"## By {name.replace('_', ' ').title()}", ""])
        lines.append("| Key | Outcomes | Confidence | Acceptance | Duplicate | Profit/hour |")
        lines.append("|---|---:|---|---:|---:|---:|")
        for row in values:
            lines.append(
                f"| {row.key} | {row.externally_resolved} | {row.confidence.value} | "
                f"{_rate(row.acceptance_rate)} | {_rate(row.duplicate_rate)} | "
                f"{_money_or_unknown(row.profit_per_review_hour_usd)} |"
            )
    lines.extend(["", "Unknown bounty values remain unknown and are not treated as revenue.", ""])
    return "\n".join(lines)


def _rate(value: float | None) -> str:
    return "unknown" if value is None else f"{value:.1%}"


def _money_or_unknown(value: Decimal | None) -> str:
    return "unknown" if value is None else f"${value}"
