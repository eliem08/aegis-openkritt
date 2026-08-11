# Effectiveness Measurement V1

## Objective

Measure whether Aegis repeatedly converts authorized opportunities into unique,
accepted, economically worthwhile findings. This milestone adds measurement and
shadow analysis only. It does not change the 32-technique execution system, the
live scheduler, policy authority, execution grants, or human submission gate.

The accepted baseline remains:

- HUMAN-HUNTER DEPTH: 78/100
- 24/7 readiness: 88/100
- Profitability readiness: 68/100
- Verdict: 24/7 SUPERVISED HUNTING READY

Profitability readiness does not increase until real outcome evidence supports it.

## Authority boundary

The active chain remains:

`MissionPlan -> PolicyEngine -> signed ExecutionGrant -> executor -> canonical evidence`

Effectiveness components may read canonical lineage and evidence. They cannot
authorize, schedule, execute, approve, or submit hunting work. Learned ranking is
persisted in shadow mode beside the existing scheduler decision and has no
production authority in V1. If effectiveness storage or analysis is unavailable,
hunting may continue with the existing scheduler and priors when the canonical
hunting runtime is otherwise healthy.

## Package boundary

A new `aegis.effectiveness` package owns:

- immutable domain records and validation;
- a shared repository interface;
- PostgreSQL production persistence and migrations;
- SQLite development/test persistence with matching semantics;
- lineage ingestion and human-reviewed outcome recording;
- aggregate metrics and confidence classification;
- shadow-ranking comparison and history;
- JSON and Markdown effectiveness reports.

The existing `JarvisStateStore.real_bounty_outcomes` path remains compatible but
is not the authoritative V1 production ledger. It will not be expanded into a
second production pathway.

## Canonical lineage and lifecycle facts

An immutable subject binds these stable identifiers and dimensions:

`run_id -> mission_id -> opportunity_id -> technique -> program_id -> asset_id`

It also records weakness family, asset class, authenticated/unauthenticated mode,
static/offline or dynamic mode, the canonical evidence digest, and the source
record digest. Lineage is validated against canonical persisted run, mission, and
opportunity material before insertion. The first insert and its lifecycle facts
are one transaction.

Append-only lifecycle facts represent:

- `OPPORTUNITY_GENERATED`;
- `FINDING_REPRODUCED`;
- `SKEPTIC_TRIAGE_SURVIVED`;
- `REPORT_HUMAN_APPROVED`;
- `REPORT_SUBMITTED`.

Each fact has a source digest and an idempotency constraint. Original hunting
evidence is never updated or copied as mutable truth.

## Outcome record

Each human-reviewed outcome version records:

- outcome state: `accepted`, `duplicate`, `informative`, `not_applicable`, or
  `rejected`;
- submitted severity and triaged severity;
- bounty in USD, preserving `NULL` when unknown or not disclosed;
- submission, triage, and resolution timestamps;
- human-review minutes;
- model/API cost and compute cost as separate non-negative decimal values;
- optional redacted analyst note;
- operator identity, recorded timestamp, source digest, and idempotency key;
- version number and optional `supersedes_outcome_event_id`.

Accepted, duplicate, informative, and N/A outcomes require a submission timestamp.
All outcomes require a resolution timestamp. Triage timestamp and severity may be
unknown but the fields remain explicit. Timestamp ordering is validated whenever
the relevant values are present.

Corrections append a new version referencing the event they supersede. They never
update or delete earlier versions. Reports and calibration use the latest valid
version per subject while retaining the complete history.

## Production storage

PostgreSQL is the only authoritative production source for outcomes, payout and
cost data, aggregates, calibration samples, and shadow-ranking history.

Migrations create logically equivalent tables for:

- `effectiveness_subjects`;
- `effectiveness_facts`;
- `effectiveness_outcome_events`;
- `effectiveness_shadow_batches`;
- `effectiveness_shadow_entries`.

Foreign keys preserve lineage inside the effectiveness ledger. Unique constraints
cover stable lineage, fact identity, outcome version, idempotency keys, and shadow
batch entries. Indexes support latest-outcome lookup and grouping by technique,
weakness, program, asset class, authentication mode, and execution mode.

PostgreSQL transactions and uniqueness constraints make concurrent ingestion
idempotent. Repeating an idempotency key with the same payload returns the original
record. Reusing it with a different payload raises an explicit conflict. Database
protections reject update or delete operations on raw subjects, facts, outcomes,
and shadow history.

SQLite implements the same repository contract and schema semantics only for
tests, fixtures, local development, and non-authoritative inspection/export.
`AEGIS_PRODUCTION=1` with a SQLite effectiveness repository raises
`EffectivenessStorageStateError` during validation. SQLite is not documented as a
production operator mode.

PostgreSQL connection failure returns an explicit `UNAVAILABLE` effectiveness
state. It cannot produce a successful write, update calibration, or enable learned
ranking authority. Production health reports learning as degraded without
misrepresenting the canonical hunting runtime as failed.

## Operator commands

### `aegis effectiveness ingest-run`

Reads a canonical persisted run or immutable manifest, validates its digests, and
records subjects and lifecycle facts. This makes opportunities without final
outcomes visible in funnel metrics. Import is read-only with respect to the hunting
runtime and idempotent in the effectiveness ledger.

### `aegis effectiveness record-outcome`

Requires an existing canonical subject and records one human-reviewed outcome or
one explicit correction. It displays the resolved lineage before write, requires
operator confirmation, preserves nullable bounty, and exits non-zero on missing
lineage, invalid timestamps, idempotency conflict, storage-state error, or database
unavailability.

### `aegis effectiveness shadow-rank`

Accepts a canonical opportunity set and persists both the existing scheduler order
and outcome-derived shadow order, scores, confidence state, sample count, and input
digest. The command does not call or modify the live scheduler.

### `aegis effectiveness report`

Produces deterministic JSON or Markdown from the authoritative repository. It
reports storage status and data freshness and never substitutes fixtures or
synthetic outcomes when production data is absent.

## Metrics

Metrics are calculated overall and separately by technique, weakness family,
program, asset class, authentication mode, and execution mode.

Counts:

- opportunities generated;
- independently reproduced findings;
- findings surviving skeptic/triage;
- human-approved reports;
- reports submitted;
- accepted, duplicate, informative, N/A, and rejected outcomes.

Economic and timing metrics:

- acceptance rate = accepted / externally resolved outcomes;
- duplicate rate = duplicates / externally resolved outcomes;
- total and median known bounty, with unknown bounty counts reported separately;
- model/API cost, compute cost, human-review cost, and total cost;
- realized profit = known bounty - recorded costs;
- time to triage;
- profit per human-review hour;
- realized EV by program as mean realized profit per resolved submission.

Externally resolved outcomes are accepted, duplicate, informative, and N/A.
Rejected is reported separately and does not silently enter the external acceptance
denominator. Zero denominators produce `NULL`, not a fabricated zero rate.

## Confidence and shadow learning

Every outcome-derived grouping is labelled:

- 0-4 resolved outcomes: `INSUFFICIENT_DATA`;
- 5-14: `LOW_CONFIDENCE`;
- 15-29: `MODERATE_CONFIDENCE`;
- 30 or more: `CALIBRATION_ELIGIBLE`.

Rates include a deterministic uncertainty interval. Below 30 resolved outcomes,
the learned shadow score uses existing priors as its economic fallback and remains
annotated as not calibration eligible. At 30 or more, the shadow calculation may
use outcome-derived acceptance, duplicate, payout, and cost estimates. It still
has no live authority in V1.

Each shadow batch preserves input opportunities, original rank and score, learned
rank and score, confidence, samples, fallback reason, and whether the shadow order
would have changed the choice. This supports later offline comparison against
realized outcomes without rewriting history.

## Report structure

The report answers where Aegis is making or losing money:

- overall funnel and economics;
- technique acceptance, duplicate rate, median payout, mean cost, and profit/hour;
- program accepted, duplicates, payout, realized EV, and profit;
- asset-class and weakness-family equivalents;
- authenticated versus unauthenticated and static/offline versus dynamic splits;
- confidence state, uncertainty, unknown-bounty count, and data freshness;
- shadow scheduler disagreements and realized comparison where outcomes exist.

V1 is a machine-readable/reporting dashboard, not a new execution UI.

## Validation

Tests must cover:

- domain validation and nullable bounty round trips;
- immutable corrections and latest-version selection;
- idempotent duplicate writes and conflicting payload rejection;
- canonical lineage and digest validation;
- metric denominators, decimal cost accounting, and unknown values;
- confidence boundaries at 0, 5, 15, and 30 samples;
- shadow ranking persistence without scheduler mutation;
- PostgreSQL migrations, indexes, update/delete rejection, rollback behavior, and
  concurrent outcome recording;
- SQLite repository contract parity;
- production-plus-SQLite fail-closed validation;
- PostgreSQL outage behavior and existing-prior fallback;
- deterministic JSON and Markdown report controls;
- CLI positive, negative, cancellation, and unavailable-backend paths.

The full existing suite, Ruff, hosted CI, Self Hunt, and both independent CVE
recall workflows must remain green.

## Non-goals

- changing the live EV scheduler;
- adding hunter techniques or scanner backends;
- automatic report submission;
- inventing outcomes, payout, or costs;
- treating unknown bounty as zero earned bounty;
- supporting SQLite as production storage;
- raising readiness or profitability scores without measured real outcomes.

## Acceptance gate

Effectiveness Measurement V1 is complete when outcome ingestion, immutable linkage,
nullable bounty, distinct duplicate/N/A states, true cost accounting, grouped
metrics, persisted shadow ranking, deterministic reports, PostgreSQL concurrency
tests, and fail-closed storage validation are implemented while production hunting
authority remains unchanged and the full branch validation is green.
