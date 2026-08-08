# Jarvis runtime consolidation

This document records which subsystem owns each responsibility while Aegis is migrated away from overlapping runtime models.

## Canonical contracts

`src/aegis/ai/agentic_os.py` is the canonical contract for:

- agent roles
- proposal risk
- action authorization
- evidence lifecycle
- shared reasoning memory
- security-reasoning graph interface

All new live-hunt integrations must produce `AgentProposal` and use `ProposalPolicy`. They must not create a new action-authority model.

## Live integration seam

`src/aegis/ai/jarvis_bridge.py` is the production bridge between `auto_hunt_run` and Jarvis. It owns:

1. validated source finding -> canonical evidence/proposal/lifecycle;
2. finding-level expected net value;
3. learned-prior calibration;
4. quality proposal gating;
5. active follow-up intent gating;
6. durable mission creation;
7. persistent security-reasoning graph writes;
8. evidence-stage advancement after real local reproduction.

The existing hunt implementation remains responsible for scanner execution, source analysis, citation validation and safe reproduction executors. The bridge decides whether additional research is authorized and economically justified.

## Graph responsibilities

Two graph concepts remain intentionally separate:

- `aegis.graph`: immutable discovery observations and the derived asset graph (domains, services, URLs, routes, parameters, technologies).
- `aegis.ai.agentic_os.SecurityKnowledgeGraph`: security reasoning relationships between repositories, findings, weaknesses, evidence and missions.

`jarvis/graph_store.py` is only the SQLite persistence adapter for the second graph. It does not introduce a third graph model.

## `active/`

`aegis.active` remains the bounded detector implementation/planner package. `active_bridge.py` is its canonical Jarvis seam.

- source findings may create an **intent** that an active lane could provide useful evidence;
- source findings never invent endpoints, identities, seeds or OAST targets;
- concrete active tasks must still be derived from discovered graph assets;
- every live active proposal is conservatively treated as `CONTROLLED_STATE_CHANGE` + network-required;
- therefore it requires network authorization, state-change authorization, sufficient request budget and human approval;
- the ordinary source-review envelope grants none of those and vetoes the proposal.

Offline operator-provided contract review remains offline.

## Economics

Target-level queue economics remain in `profit.py`/`AutoHunter` for compatibility. Finding-level escalation uses the common `portfolio_agents.Opportunity` contract and durable priors from `JarvisStateStore`.

A source-confirmed finding is **not** a bounty outcome. Acceptance, duplicate and payout priors must be updated only from real program outcomes.

## Compatibility debt

`jarvis/models.py`, `jarvis/council.py` and `jarvis/economics.py` predate `agentic_os` and contain overlapping enums/contracts. They remain compatibility modules until their callers are migrated. New production code must not depend on those duplicate contracts.

Migration rule: adapt existing callers to `agentic_os` incrementally, add tests, then deprecate/remove the old contract only when repository search shows no live callers.

## Evidence rule

The canonical lifecycle is:

`candidate -> source_supported -> runtime_observed -> oracle_passed -> locally_reproduced -> independently_verified -> human_approved -> submission_ready`

No string assignment may skip stages. Each autonomous transition requires evidence. Human approval is never synthesized by an agent.
