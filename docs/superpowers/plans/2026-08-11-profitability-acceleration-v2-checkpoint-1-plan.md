# Profitability Acceleration V2 — Checkpoint 1 Plan

## Goal

Extend the canonical Effectiveness V1 ledger with backward-compatible lineage,
funnel, outcome, and true-cost semantics. Stop and report before implementing
statistical profitability.

## Invariants

- PostgreSQL remains the only authoritative production effectiveness store.
- Migrations are additive; V1 rows and payload meanings are never rewritten.
- Raw subjects, facts, outcomes, and costs are immutable and append-only.
- Unknown monetary values remain `NULL`; explicit zero remains zero.
- Human dollars exist only with a snapshotted operator-supplied hourly rate.
- Derived economics are deterministic projections, never canonical facts.
- The scheduler, PolicyEngine, ExecutionGrant, executors, and submission gate do
  not import or depend on V2 recommendation code.

## 1. Lock behavior with failing tests

Extend `tests/effectiveness/` with domain and repository contract tests for:

- `PENDING` and `WITHDRAWN` outcomes;
- all canonical funnel transitions, including separate acceptance and payment;
- nullable V2 lineage fields on historical V1 subjects;
- required V2 lineage validation for new stage-specific records;
- immutable, idempotent cost observations;
- identical retry versus conflicting idempotency payload;
- nullable cost components and explicit zero;
- human minutes without rate, rate snapshots, and calculated human cost;
- complete and incomplete realized-profit projections;
- versioned outcome corrections and immutable raw rows.

Add PostgreSQL tests for concurrent identical cost writes, conflicting writes,
immutability triggers, and V1-to-V2 migration preservation.

## 2. Extend canonical domain models

Update `src/aegis/effectiveness/models.py`:

- retain existing enum values and add canonical V2 outcome/funnel values;
- add nullable `candidate_finding_id`, `human_decision_id`, and `submission_id`
  lineage to `EffectivenessSubject` without changing historical V1 meaning;
- add versioned structured fact metadata;
- add immutable `CostObservation` and `CostRecord` models;
- centralize nullable non-negative Decimal validation;
- implement deterministic labor-cost calculation using the snapshotted rate;
- expose a versioned `EconomicProjection` with both realized-profit fields and
  an explicit completeness state.

## 3. Add additive schema migrations

Update `repository.py` and `postgres.py` with migration version 2:

- add nullable V2 lineage columns to subjects;
- add fact metadata and model-version columns without rewriting stored values;
- add immutable `effectiveness_cost_observations` with source/idempotency
  digests, nullable components, human fields, and cost-calculation version;
- add lookup and grouping indexes;
- add update/delete rejection triggers;
- retain the V1 migration checksum and apply V2 independently under the
  existing migration lock.

SQLite must mirror the logical schema for tests/development. Migration tests
will create a V1 database first, insert historical rows, upgrade it, and verify
that original values/digests remain unchanged and new fields are `NULL`.

## 4. Extend the repository contract

Add repository operations to:

- append an idempotent fact to an existing subject;
- append an idempotent cost observation;
- list facts and costs deterministically by subject/campaign;
- reject missing lineage, mismatched subject linkage, conflicting retries, and
  cost observations whose computed human cost disagrees with the supplied rate.

PostgreSQL writes use transactions, advisory locks, and database constraints.
No unavailable write may be reported as successful.

## 5. Implement economic projections

Add a focused deterministic projection module that aggregates raw cost
observations without statistical modeling. It calculates:

- total human minutes;
- snapshotted human monetary cost when all applicable rates are known;
- known machine/infrastructure cost components;
- `realized_profit_excluding_human_cost_usd` only with complete required
  machine/infrastructure cost and revenue;
- `realized_profit_usd` only when all required monetary costs, including human
  cost, are complete;
- explicit missing-input names and `ECONOMICS_INCOMPLETE` state.

Existing V1 metrics remain backward-compatible during Checkpoint 1. Statistical
probability, payout, EV, stop-loss, and bandit work is deferred to later
checkpoints.

## 6. Validate and checkpoint

Run:

- focused effectiveness unit/integration tests;
- the real PostgreSQL 16 concurrency and migration lane;
- canonical scheduler/authority regressions;
- Ruff and diff checks;
- the full suite if focused checks are green.

Commit logical implementation layers. Report exact schema/model changes, test
counts, PostgreSQL results, compatibility proof, nullable economics controls,
and confirmation that production scheduling authority is unchanged. Do not
start Checkpoint 2 until the operator accepts the report.
