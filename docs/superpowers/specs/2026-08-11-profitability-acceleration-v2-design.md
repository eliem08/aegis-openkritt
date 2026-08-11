# Profitability Acceleration V2 Design

Date: 2026-08-11

Status: Approved

## Objective

Extend Effectiveness Measurement V1 so Aegis can measure and recommend hunting
work according to unique accepted bounty value minus machine, infrastructure,
and explicitly priced human cost. V2 remains measurement and recommendation
only. It does not change the 32-technique runtime, scheduler authority,
PolicyEngine, signed ExecutionGrant flow, scoped executors, or mandatory human
submission.

## Authority Boundary

The effectiveness ledger may ingest immutable observations, derive projections,
and recommend priorities. It cannot authorize, schedule, execute, or submit.

The active authority chain remains:

```text
ProgramSnapshot
-> scope digest
-> operator selection
-> MissionPlan
-> PolicyEngine
-> signed ExecutionGrant
-> scoped executor
-> canonical evidence
-> human review
-> human submission
```

Learned ranking, stop-loss, and exploration outputs remain shadow-only. Missing
effectiveness storage or incomplete economics cannot grant authority and cannot
replace the existing scheduler priors.

## Canonical Data Model

V2 extends the V1 PostgreSQL ledger additively. SQLite mirrors repository
semantics only for tests and local development and remains invalid when
`AEGIS_PRODUCTION=1`.

### Lineage

Every V2 observation resolves through the canonical chain:

```text
program -> asset -> run -> opportunity -> mission -> technique
-> candidate finding -> human decision -> submission -> program outcome
```

Existing V1 subject rows remain valid and unchanged. New lineage columns are
nullable for historical V1 records. New V2 operations validate the identifiers
required for their specific stage; they never invent or backfill missing
candidate, decision, or submission identifiers.

### Funnel Facts

`EffectivenessFact` remains append-only and gains the canonical stages:

1. `opportunity_generated`
2. `candidate_generated`
3. `runtime_observed`
4. `locally_reproduced`
5. `independently_verified`
6. `human_approved`
7. `submitted`
8. `triaged`
9. `accepted`
10. `paid`

The first nine named business transitions are retained separately; `paid` is an
additional terminal monetary event required to distinguish acceptance from
payment. Legacy V1 fact names remain readable aliases with their original stored
values and are not rewritten. New writes use canonical V2 names.

Each fact carries immutable identity, subject linkage, observation timestamp,
source digest, idempotency key, and versioned structured metadata where needed.
Duplicate idempotency keys replay only when their entire immutable payload is
identical; materially different payloads conflict.

### Outcomes and Corrections

Canonical states are:

```text
ACCEPTED, DUPLICATE, INFORMATIVE, N_A, REJECTED,
WITHDRAWN, PENDING
```

Corrections append a new version linked by `supersedes_outcome_event_id`. No raw
outcome is updated or deleted. `PENDING` is not counted as externally resolved.
Human decisions and external program outcomes remain distinguishable through
lineage and stage facts.

### Cost Observations

Costs are append-only observations linked to the most precise available
canonical subject, opportunity, mission, or campaign. Components are:

- model/API cost;
- scanner compute cost;
- cloud cost;
- OAST cost;
- browser/device cost;
- human review minutes;
- human submission minutes;
- human other minutes;
- operator-supplied human hourly rate.

Every monetary field is nullable. Unknown is distinct from an explicitly
recorded zero. Human minutes are recorded whenever known. Human monetary cost is
calculated only when an hourly rate is supplied:

```text
human_cost_usd =
  (human_review_minutes + human_submission_minutes + human_other_minutes)
  / 60
  * human_hourly_rate_usd
```

The observation snapshots the rate and cost-calculation version. Later default
rate changes do not alter historical calculations. No wage, salary, bounty, or
market-rate inference is permitted.

Legacy V1 outcome cost fields retain their original meaning. Migration does not
reinterpret absent data or convert it into zero. Explicit historical values may
be projected through a versioned V1 compatibility adapter without modifying raw
rows.

## Economic Semantics

Raw facts, outcomes, and cost observations are canonical. All totals,
probabilities, scores, and rankings are deterministic projections.

V2 exposes:

```text
realized_profit_excluding_human_cost_usd
realized_profit_usd
```

The first is revenue minus all required known machine and infrastructure costs.
It is `NULL` if any required machine/infrastructure component is unknown.

The second also subtracts human cost and remains `NULL` when the hourly rate or
any required monetary component is unknown. Missing bounty, payout, or cost is
never treated as zero.

Derived records and report sections include:

- `sample_count`;
- `confidence_class`;
- `model_version`;
- `computed_at`;
- the deterministic input/configuration digest.

Recomputation with the same immutable inputs and model configuration produces
identical numerical output. `computed_at` records projection execution time and
does not participate in numerical calculations.

## Statistical Profitability

V2 derives uncertainty-aware `P_VALID`, `P_UNIQUE`, and `P_ACCEPTED` from real
funnel and outcome observations. Models use explicit, versioned smoothing priors
and intervals rather than raw tiny-sample point estimates. Hierarchical fallback
may pool broader dimensions only through a documented model version and must
retain the local and pooled sample counts.

Confidence classes remain:

```text
0-4    INSUFFICIENT_DATA
5-14   LOW_CONFIDENCE
15-29  MODERATE_CONFIDENCE
30+    CALIBRATION_ELIGIBLE
```

Payout estimates use only known, accepted, real payouts grouped by program,
severity, weakness family, and asset class. Advertised maximums are excluded.
When evidence is insufficient, expected payout is `NULL`.

Shadow EV is:

```text
P_VALID * P_UNIQUE * P_ACCEPTED * EXPECTED_PAYOUT
- EXPECTED_COST
```

If payout or required cost evidence is incomplete, status is
`ECONOMICS_INCOMPLETE`; the system emits non-payout utility and existing-prior
fallback ranking instead of a fabricated EV. It also reports `EV_PER_HOUR`,
`EV_PER_REQUEST`, and `EV_PER_COMPUTE_DOLLAR` only when their denominators and
required inputs are known.

Metrics are projected overall and by technique, weakness family, program, asset
class, authentication mode, execution mode, severity, and the critical matrix:

```text
program x asset class x technique x weakness family
```

Program-local evidence cannot globally demote a technique.

## Duplicate and Acceptance Intelligence

Duplicate risk uses only legitimate public context and internal authorized
outcome evidence. Versioned features may include program, asset class and
popularity, technique, weakness family, endpoint/asset age when known, exposure,
recent similar candidates, and historical duplicate outcomes. Unknown feature
values remain unknown.

Outputs carry posterior estimates, uncertainty, sample counts, confidence, model
version, and computation time. No private report scraping is introduced.

## Shadow Policy

The shadow policy persists existing and learned orderings, selection flags,
scores, confidence, model/config version, and input digest for every scheduling
decision. It may recommend `CONTINUE`, `DEPRIORITIZE`, or `STOP`, but cannot act
on that recommendation.

Exploration/exploitation is a deterministic, versioned shadow simulation using
an uncertainty-aware allocation, initially configurable within 80-90% exploit
and 10-20% explore. It never authorizes execution.

When outcomes arrive, the ledger attaches factual realized reward to the actual
selection. A shadow hypothetical reward is populated only when it is observable
from canonical evidence. It remains `NULL` for an unselected alternative whose
outcome is unknowable; V2 does not manufacture counterfactual labels.

## Operator Workflows

The CLI provides:

```text
aegis effectiveness record-outcome
aegis effectiveness amend-outcome
aegis effectiveness pending
aegis effectiveness report
aegis effectiveness daily
```

Recording and amendment support interactive terminal input and manifest/JSON
input. Commands resolve and display lineage before confirmation, do not accept or
persist secrets, and preserve idempotency and immutable correction rules.

The pending and human-review queues rank candidates using reproducibility,
impact, uniqueness, program fit, shadow economics, and evidence/report quality.
Operators may append decisions such as `APPROVE_FOR_SUBMISSION`, `REJECT`,
`NEEDS_MORE_EVIDENCE`, and `LIKELY_DUPLICATE`. Submission remains external and
human-only.

Report-quality projections check title, affected asset, reproduction steps,
observed/expected result, impact, evidence, negative controls, scope proof, and
provenance without submitting anything.

## Campaigns

Campaign records contain campaign ID, program, policy/scope references, time and
cost budgets, selected assets, allowed techniques, start/end timestamps, and
immutable event history. They reuse canonical production scope, policy, mission,
grant, and evidence identifiers rather than implementing authorization.

A campaign report includes opportunities, verified candidates, human approvals,
submissions, known and unknown costs, projected value, and later external
outcomes. Running a real campaign requires operator-supplied current
authorization and target selection. V2 does not select or attack a target by
itself.

## Reports

Deterministic JSON and Markdown reports answer whether hunting is making money
and expose totals, funnel drop-off, programs, techniques, asset classes,
weaknesses, the program-technique matrix, shadow comparisons, and confidence.

The daily report covers hunted work, reproduction, pending review, submissions,
changed outcomes, known revenue and cost, incomplete economics, effective
techniques, duplicate sinks, and shadow-only allocation recommendations.

Reports explicitly show record counts and missing-data counts. Empty or synthetic
data cannot be presented as realized profitability.

## Error and Availability Semantics

- Production PostgreSQL failure produces no successful effectiveness write.
- Existing hunting may continue when its canonical runtime is healthy.
- Learned recommendations become degraded/unavailable and existing priors remain.
- Invalid lineage, stale references, idempotency conflicts, and tampered payloads
  fail closed.
- Missing monetary inputs produce `NULL` and `ECONOMICS_INCOMPLETE`.
- No missing backend, input, or outcome becomes a successful observation.

## Delivery Checkpoints

### Checkpoint 1: Canonical lineage, funnel, and cost semantics

Deliver additive migrations, backward-compatible models/repositories, full
lineage validation, expanded outcomes and facts, immutable cost observations,
labor-rate snapshots, nullable profit semantics, and PostgreSQL concurrency and
immutability tests. Stop for a checkpoint report before statistical work.

### Checkpoint 2: Statistical profitability

Deliver versioned uncertainty-aware probability and payout projections,
confidence gates, program/technique/matrix metrics, incomplete-economics handling,
and deterministic projection tests.

### Checkpoint 3: Shadow policy

Deliver EV V2, time-adjusted metrics, duplicate risk, stop-loss recommendations,
exploration/exploitation simulation, and actual-versus-shadow/counterfactual
storage. Production authority remains unchanged.

### Checkpoint 4: Operator workflows

Deliver ergonomic outcome/amendment commands, pending and review queues,
campaigns, daily report, JSON/Markdown dashboard, report-quality metrics, and
full operational documentation.

## Validation and Completion Gates

Each checkpoint requires unit, integration, negative, fail-closed, migration,
and PostgreSQL tests appropriate to its scope. The branch must keep Ruff and the
existing canonical-runtime regressions green.

V2 completion additionally requires concurrent PostgreSQL writes, immutable
corrections and costs, full pytest, hosted PostgreSQL, CI, Self Hunt, deterministic
reports, and proof that scheduler/execution authority did not change.

No real outcome, submission, revenue, cost, or counterfactual is invented. The
profitability readiness score remains 68/100 until real external observations
justify a separate evidence-based reassessment.
