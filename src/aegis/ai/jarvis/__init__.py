"""Agent-first Aegis/Jarvis security research operating system."""

from .advanced import build_jarvis as build_advanced_jarvis
from .council import (
    DEFAULT_COUNCIL,
    EvidenceAgent,
    JarvisCommander,
    ProfitabilityAgent,
    ReportAgent,
    ReproductionAgent,
    SkepticAgent,
)
from .coverage import CoverageCell, blind_spot_score, prioritize_blind_spots
from .economics import (
    EconomicEstimate,
    PortfolioScheduler,
    ProgramArm,
    estimate_hypothesis,
)
from .firewall import (
    ContentAssessment,
    assess_untrusted_content,
    envelope_untrusted_source,
)
from .guards import PolicyGate
from .hunt_generator import SurfaceSignal, generate_hunt_candidates, infer_surfaces
from .hunt_lanes import HuntLane, lane_for_family
from .learning_agents import (
    BountyOutcome,
    ConfirmedFinding,
    CoverageOptimizerAgent,
    MissionSchedulerAgent,
    OutcomeLearningAgent,
    RuleSynthesisAgent,
    VulnerabilityFamilyAgent,
)
from .memory import AgentMemory, MemoryRecord
from .mission_scheduler import (
    MissionPlan,
    MissionScheduler,
    MissionTask,
    TaskState,
    build_linear_mission,
)
from .models import (
    ActionProposal,
    AgentResult,
    AgentRole,
    EvidenceStage,
    FindingState,
    GateDecision,
    HuntObjective,
    ResearchHypothesis,
    RiskClass,
    RuntimePlan,
    SecurityInvariant,
)
from .profit_controls import (
    CandidateDisposition,
    ProgramEligibility,
    ResearchRunMetrics,
    StopLossAgent,
    StopLossDecision,
    evaluate_stop_loss,
)
from .profit_feedback import (
    calibrate_opportunities,
    calibrate_opportunity,
    prior_weight,
    rank_calibrated_opportunities,
)
from .research import HypothesisAgent, InvariantAgent, JsonModelClient
from .rule_factory import (
    RuleDraft,
    RuleValidationResult,
    draft_detection_rule,
    to_record,
    validate_rule_fixture_counts,
)
from .severity_portfolio import SeverityPortfolioPolicy, select_diverse_candidates
from .state_store import (
    CoverageObservation,
    JarvisStateStore,
    LearnedPrior,
    MissionSnapshot,
    RuleCandidateRecord,
    VulnerabilityFamily,
)
from .universal_mission import compile_candidate_mission
from .weakness_catalog import (
    UNIVERSAL_FAMILIES,
    HuntCandidate,
    SeverityTier,
    WeaknessFamily,
    families_for_surface,
    rank_candidates,
)
from .weakness_planner import (
    ChainableFinding,
    ChainOpportunity,
    ChainReasoningAgent,
    UniversalHuntAgent,
    chain_opportunities,
)

__all__ = [
    "DEFAULT_COUNCIL",
    "UNIVERSAL_FAMILIES",
    "ActionProposal",
    "AgentMemory",
    "AgentResult",
    "AgentRole",
    "BountyOutcome",
    "CandidateDisposition",
    "ChainOpportunity",
    "ChainReasoningAgent",
    "ChainableFinding",
    "ConfirmedFinding",
    "ContentAssessment",
    "CoverageCell",
    "CoverageObservation",
    "CoverageOptimizerAgent",
    "EconomicEstimate",
    "EvidenceAgent",
    "EvidenceStage",
    "FindingState",
    "GateDecision",
    "HuntCandidate",
    "HuntLane",
    "HuntObjective",
    "HypothesisAgent",
    "InvariantAgent",
    "JarvisCommander",
    "JarvisStateStore",
    "JsonModelClient",
    "LearnedPrior",
    "MemoryRecord",
    "MissionPlan",
    "MissionScheduler",
    "MissionSchedulerAgent",
    "MissionSnapshot",
    "MissionTask",
    "OutcomeLearningAgent",
    "PolicyGate",
    "PortfolioScheduler",
    "ProfitabilityAgent",
    "ProgramArm",
    "ProgramEligibility",
    "ReportAgent",
    "ReproductionAgent",
    "ResearchHypothesis",
    "ResearchRunMetrics",
    "RiskClass",
    "RuleCandidateRecord",
    "RuleDraft",
    "RuleSynthesisAgent",
    "RuleValidationResult",
    "RuntimePlan",
    "SecurityInvariant",
    "SeverityPortfolioPolicy",
    "SeverityTier",
    "SkepticAgent",
    "StopLossAgent",
    "StopLossDecision",
    "SurfaceSignal",
    "TaskState",
    "UniversalHuntAgent",
    "VulnerabilityFamily",
    "VulnerabilityFamilyAgent",
    "WeaknessFamily",
    "assess_untrusted_content",
    "blind_spot_score",
    "build_advanced_jarvis",
    "build_linear_mission",
    "calibrate_opportunities",
    "calibrate_opportunity",
    "chain_opportunities",
    "compile_candidate_mission",
    "draft_detection_rule",
    "envelope_untrusted_source",
    "estimate_hypothesis",
    "evaluate_stop_loss",
    "families_for_surface",
    "generate_hunt_candidates",
    "infer_surfaces",
    "lane_for_family",
    "prior_weight",
    "prioritize_blind_spots",
    "rank_calibrated_opportunities",
    "rank_candidates",
    "select_diverse_candidates",
    "to_record",
    "validate_rule_fixture_counts",
]
