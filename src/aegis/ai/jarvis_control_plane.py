"""Canonical subsystem ownership for the Jarvis/Aegis control plane.

The repository intentionally has several layers that can look duplicated when viewed only by
folder name. This module makes the ownership boundary executable: one responsibility has one
canonical subsystem, and the source-review lane can inspect which lower layers are live versus
network-capable/dormant.

This is a registry and health adapter only. Importing it never starts workers, scanners, Redis,
HTTP servers, active probes, or target-facing network requests.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import asdict, dataclass
from enum import Enum


class Responsibility(str, Enum):
    SOURCE_REVIEW_PIPELINE = "source_review_pipeline"
    FINDING_LIFECYCLE = "finding_lifecycle"
    FINDING_MISSION = "finding_mission"
    ASSET_INGEST = "asset_ingest"
    ASSET_OBSERVATION_GRAPH = "asset_observation_graph"
    SECURITY_REASONING_GRAPH = "security_reasoning_graph"
    HISTORICAL_KNOWLEDGE = "historical_knowledge"
    ENGAGEMENT_SCHEDULER = "engagement_scheduler"
    DISTRIBUTED_COORDINATION = "distributed_coordination"
    ACTIVE_DETECTOR_LOOP = "active_detector_loop"
    NETWORK_POLICY = "network_policy"
    MODEL_TRANSPORT = "model_transport"


@dataclass(frozen=True)
class SubsystemAuthority:
    responsibility: Responsibility
    module: str
    purpose: str
    source_review_live: bool
    target_network_capable: bool = False


AUTHORITIES: tuple[SubsystemAuthority, ...] = (
    SubsystemAuthority(
        Responsibility.SOURCE_REVIEW_PIPELINE,
        "aegis.ai.auto_hunt_run",
        "authorized clone/source analysis -> validation -> council -> local repro -> report",
        True,
    ),
    SubsystemAuthority(
        Responsibility.FINDING_LIFECYCLE,
        "aegis.ai.agentic_os",
        "canonical evidence stages, proposal policy, shared memory and reasoning graph contract",
        True,
    ),
    SubsystemAuthority(
        Responsibility.FINDING_MISSION,
        "aegis.ai.jarvis.mission_scheduler",
        "finding-level dependency checkpoints and resumable Jarvis mission state",
        True,
    ),
    SubsystemAuthority(
        Responsibility.ASSET_INGEST,
        "aegis.adapters",
        "tool/provider normalization into immutable observations",
        False,
        True,
    ),
    SubsystemAuthority(
        Responsibility.ASSET_OBSERVATION_GRAPH,
        "aegis.graph",
        "deduplicated asset topology derived from immutable adapter observations",
        False,
        True,
    ),
    SubsystemAuthority(
        Responsibility.SECURITY_REASONING_GRAPH,
        "aegis.ai.jarvis_graph",
        "persistent program/repository/finding/evidence reasoning relationships",
        True,
    ),
    SubsystemAuthority(
        Responsibility.HISTORICAL_KNOWLEDGE,
        "aegis.knowledge",
        "disclosed-report corpus and bounded historical priors",
        True,
    ),
    SubsystemAuthority(
        Responsibility.ENGAGEMENT_SCHEDULER,
        "aegis.scheduler",
        "durable scans/stages/tasks/leases/artifacts and generic EV allocation kernel",
        False,
        True,
    ),
    SubsystemAuthority(
        Responsibility.DISTRIBUTED_COORDINATION,
        "aegis.coord",
        "ephemeral rate buckets, semaphores, cancellation, dedup and worker identity",
        False,
        True,
    ),
    SubsystemAuthority(
        Responsibility.ACTIVE_DETECTOR_LOOP,
        "aegis.orchestrator",
        "in-process policy-gated detector planning/execution loop",
        False,
        True,
    ),
    SubsystemAuthority(
        Responsibility.NETWORK_POLICY,
        "aegis.gateway",
        "single target-facing outbound-network policy authority",
        False,
        True,
    ),
    SubsystemAuthority(
        Responsibility.MODEL_TRANSPORT,
        "aegis.model_gateway",
        "authenticated, budgeted, cached model-call boundary",
        True,
        False,
    ),
)


def validate_authority_map() -> None:
    """Fail fast if a responsibility is assigned twice or a canonical package vanished."""
    responsibilities = [item.responsibility for item in AUTHORITIES]
    if len(responsibilities) != len(set(responsibilities)):
        raise RuntimeError("control-plane responsibility has multiple canonical owners")
    for item in AUTHORITIES:
        importlib.import_module(item.module)


def authority_for(responsibility: Responsibility | str) -> SubsystemAuthority:
    target = Responsibility(responsibility)
    for item in AUTHORITIES:
        if item.responsibility is target:
            return item
    raise KeyError(target)


def source_review_guard_report() -> dict:
    """Return the source-review boundary and prove target-network work is vetoed."""
    from .jarvis_runtime import evaluate_tier3_source_review

    evaluated = evaluate_tier3_source_review()
    return {
        "source_review_live": [
            item.responsibility.value for item in AUTHORITIES if item.source_review_live
        ],
        "target_network_dormant": [
            item.responsibility.value for item in AUTHORITIES if item.target_network_capable
        ],
        "tier3": [
            {
                "action": proposal.action,
                "approved": bool(decision.approved),
                "reason": decision.reason,
            }
            for proposal, decision in evaluated
        ],
        "model_transport": (
            "gateway" if os.environ.get("AEGIS_MODEL_GATEWAY_URL", "").strip() else "direct-dev"
        ),
    }


def ownership_snapshot() -> list[dict]:
    """Serializable ownership map for diagnostics/dashboard surfaces."""
    return [
        asdict(item) | {"responsibility": item.responsibility.value}
        for item in AUTHORITIES
    ]
