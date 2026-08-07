"""Automatic hunting loop (discover -> scan -> collect -> learn -> repeat).

Human-supervised by construction: it never exploits and never submits, only scans
authorized automation-permitted code-repo scope, and is dry-run until armed. See
:mod:`aegis.hunt.orchestrator`.
"""

from .orchestrator import HuntConfig, HuntOrchestrator, HuntReport
from .reward import (
    DEFAULT_REWARD_POLICIES,
    RewardPolicy,
    eligibility,
    load_reward_policies,
    meets_floor,
)

__all__ = [
    "DEFAULT_REWARD_POLICIES",
    "HuntConfig",
    "HuntOrchestrator",
    "HuntReport",
    "RewardPolicy",
    "eligibility",
    "load_reward_policies",
    "meets_floor",
]
