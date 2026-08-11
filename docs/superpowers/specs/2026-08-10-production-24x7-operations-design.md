# Production 24x7 Operations Design

## Objective

Move Aegis from **SUPERVISED HUNTING READY** to **24/7 SUPERVISED HUNTING
READY** by proving sustained operation. This milestone adds no hunter-technique
breadth and does not change the profitability score without real outcome data.

The six promotion gates are:

1. a green six-hour real-worker soak;
2. restart-safe 24-hour operator soak support;
3. operational production dependency health checks;
4. one explicitly authorized real-program dry run;
5. one controlled supervised live canary; and
6. separately measured whole-repository CVE discovery recall.

Human submission remains mandatory. The runtime invariant remains:

`planned != authorized != executed != observed != reproduced != verified != human-approved != submission-ready`

## Canonical boundaries

The operator workflow reuses the existing program ingestion, scope graph,
`HuntOpportunity`, economic scoring, `MissionPlan`, policy engine, signed
`ExecutionGrant`, scoped executors, canonical evidence, persistence, leases,
heartbeats, recovery, and kill switch. It does not introduce parallel authority,
scheduling, evidence, or execution paths.

`reports/programs.json` may pre-populate candidate programs only. Its contents
never authorize execution. Every real run requires an operator-selected program,
a fresh policy and scope refresh, explicit asset selection, a new scope digest,
and a signed authorization produced by the canonical policy authority.

## Operator interface and immutable run manifest

The manifest-driven CLI has three primary operations:

- `aegis production health` reports machine-readable dependency readiness;
- `aegis production operator dry-run` refreshes scope, ranks opportunities, and
  compiles missions without executing them; and
- `aegis production operator live-canary` executes bounded read-only missions on
  one explicitly selected current in-scope asset.

Each run persists an append-only manifest containing the policy snapshot and
digest, scope snapshot and digest, selected program and assets, operator
selections, controlled identity references, request/rate/cost budgets, signed
grant references, mission identifiers, evidence references, event timeline, and
final status. Resume validates the prior hashes and continues from the last
durable event. Mutable credentials are referenced by operator-defined identifiers
and are never copied into the manifest.

Dry-run mode stops after opportunity ranking and mission compilation. Live-canary
mode defaults to one asset and read-only execution. Any state-changing task is
blocked unless it carries a separate signed approval for that exact action,
asset, scope digest, budget, and validity window.

## Production health

The health command reports independent READY, WAITING_FOR_PREREQUISITE,
UNAVAILABLE, or FAILED cells for policy authority, database, worker leases,
certificate-transparency provider, private OAST, Playwright, Android runtime,
gRPC prerequisites, scanner versions, scoped network executor, artifact
acquisition, and model providers. It performs bounded non-target probes only.
Required cells that are not READY make the command fail closed with a non-zero
exit code; optional cells remain explicit without becoming fake successes.

## Sustained operation

The soak runner launches real worker processes and records heartbeats, lease
claims and renewals, process restarts, provider outages, authorization revocation,
kill-switch events, request/cost exhaustion, evidence durability, and task
completion identifiers. The report includes checkpoints, health samples, a
failure timeline, and a duplicate state-changing execution audit.

Six-hour mode requires at least 21,600 seconds. Twenty-four-hour mode requires at
least 86,400 seconds and resumes an existing report safely after operator or host
restart. The modes and their evidence are reported separately.

## CVE measurement

The existing `path_hinted_ground_truth_recall` is retained unchanged: it asks
whether Aegis detects a weakness when scanning the independently verified
vulnerable source area.

A second `whole_repository_discovery_recall` scans complete vulnerable and fixed
revisions without supplying advisory path hints to discovery. A case is detected
only when the normal full-repository pipeline independently surfaces a matching
weakness on the vulnerable revision and the fixed revision remains a negative
control. Unavailable tools, invalid provenance, and skipped cases remain distinct
from misses. Reports store both metrics under different keys and never combine,
average, or relabel them.

## Promotion and economics

Promotion remains blocked until every six-hour/24-hour prerequisite above has
measured evidence, including an authorized real-program dry run and supervised
live canary. The profitability readiness score remains unchanged until real
accepted, duplicate, informative, N/A, severity, bounty, triage-time, and cost
outcomes populate the existing learner.
