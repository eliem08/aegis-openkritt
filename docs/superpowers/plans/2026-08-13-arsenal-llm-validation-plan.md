# Arsenal and AI/LLM Validation Implementation Plan

## Checkpoint 1: Canonical inventory and audit

1. Add immutable capability, provenance, conflict, health, and coverage models.
2. Federate tool, adapter, deep-asset, hunter-technique, executor, and release-lock registries.
3. Add bounded backend/version probes and verified historical-run projection.
4. Add deterministic JSON/Markdown reporting and `aegis arsenal audit`.
5. Test stable IDs, conflicts, non-targeting behavior, evidence integrity, and rendering.

## Checkpoint 2: Coverage ledger

1. Add a shared repository interface and migrations.
2. Implement SQLite for tests/development and PostgreSQL for production authority.
3. Enforce append-only, idempotent, concurrency-safe coverage writes.
4. Reject SQLite when `AEGIS_PRODUCTION=1`.
5. Test immutable replay/conflict and PostgreSQL concurrency semantics.

## Checkpoint 3: Canonical fixture exercise

1. Add versioned fixture definitions and `LOCAL_FIXTURE_ONLY` authorization.
2. Compile exercises into HuntOpportunity, MissionPlan, PolicyEngine, signed grants,
   existing executors, and immutable evidence.
3. Add capability-specific negative controls and structured failure classes.
4. Add resume/non-replay, monotonic budgets, kill-switch, and degraded-ledger handling.
5. Add `aegis arsenal exercise` with JSON/Markdown artifacts.

## Checkpoint 4: AI/LLM security lab

1. Add deterministic two-user/two-campaign agent fixture with isolated memory/RAG/tools.
2. Add four synthetic canary classes and versioned deterministic oracles.
3. Implement the 16 required canonical attack cases, including multi-turn persistence and
   evidence forgery.
4. Record independent model-behavior and system-boundary verdicts.
5. Add optional real-provider execution of the identical case set without execution authority.

## Checkpoint 5: Fixture coverage expansion

1. Exercise available offline scanners against deterministic positive and negative fixtures.
2. Exercise isolated local network/API/browser fixtures where safe backends exist.
3. Exercise available mobile, binary, firmware, and contract fixtures.
4. Persist explicit unavailable/waiting/backend-unhealthy states for missing real backends.

## Checkpoint 6: Validation and delivery

1. Run focused tests after each checkpoint.
2. Run Ruff, full pytest, benchmark, Self Hunt, and PostgreSQL integration lane.
3. Generate the final arsenal audit and AI/LLM validation evidence.
4. Report the requested A-AJ results without merging fixture and authorized-real metrics or
   changing profitability readiness.
