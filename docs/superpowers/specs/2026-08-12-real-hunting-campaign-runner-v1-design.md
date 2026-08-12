# Real Hunting Campaign Runner V1

## Objective

Add a thin canonical campaign coordinator that turns an operator-supplied, freshly authorized
bug-bounty campaign into bounded execution and measured effectiveness evidence. It reuses the
existing operator workflow, policy authority, universal hunt runtime, durable scheduler,
executors, evidence store, human-review queue, and PostgreSQL effectiveness ledger. It adds no
new hunting architecture and never submits reports automatically.

GitLab and Atlassian are initial candidate campaigns, not authorization. Each campaign requires
a current authoritative policy/scope snapshot and explicit operator selections at execution time.

## Authority Model

Executable capability is computed independently for each technique, asset, and context:

`requested techniques AND policy permissions AND asset eligibility AND operator approvals AND safe available backends`

The coordinator and policy adapters only produce evidence-backed decisions. Authority remains:

`PolicyEngine -> signed ExecutionGrant -> scoped executor`

Free-form program rules never become permission through optimistic inference. A policy adapter
must produce a typed permission backed by reproducible provenance: source URL/reference,
snapshot timestamp and digest, parsed rule ID, adapter version, and exact evidence span or
structured scope row. Ambiguous or unsupported language fails closed.

## Technique Authorization Decision

Every requested technique + asset + context produces an immutable, versioned
`TechniqueAuthorizationDecision` containing:

- technique, program, asset, and execution context;
- policy snapshot digest, rule IDs, adapter version, and evidence provenance;
- campaign-scoped operator approval ID and validity window;
- controlled identity references without credential material;
- backend name and version;
- typed technique-specific constraints;
- request, rate, concurrency-attempt, time, and cost budgets;
- status, denial reason, and nullable grant ID.

Statuses remain distinct:

- `AUTHORIZED`
- `WAITING_FOR_PREREQUISITE`
- `UNAVAILABLE`
- `DENIED`
- `DENIED_POLICY_AMBIGUOUS`
- `DENIED_ASSET_INELIGIBLE`
- `DENIED_OPERATOR_APPROVAL`
- `DENIED_BACKEND_UNSAFE`
- `DENIED_CONSTRAINT_UNENFORCEABLE`

Operator approvals are versioned and bound to campaign, technique, asset, context, identities,
and time window. Grants bind translated constraints, not only technique names. Examples include
race concurrency and attempt bounds, operator-owned object context, required state verification,
OAST destination/callback budgets, upload limits and cleanup, and exact protocol destinations.

Destructive activity, persistence, credential theft or guessing, stealth/evasion, uncontrolled
DoS, and activity against non-consenting users/assets remain unavailable unless the current
program explicitly permits the exact behavior and Aegis has a safe enforceable implementation.

## Runtime Flow

1. The operator supplies one campaign manifest: program reference, selected assets, requested
   techniques, identity references, approvals, duration, and cost ceiling.
2. Aegis refreshes the authoritative program policy and scope and persists the immutable snapshot.
3. Policy adapters translate supported rules into typed, provenance-backed permissions.
4. Aegis creates and persists one authorization decision per technique + asset + context.
5. Authorized decisions feed the existing HuntOpportunity generator and scheduler. Actual and
   shadow rankings are persisted independently.
6. The canonical runtime compiles `MissionPlan` and `MissionTask` objects.
7. Eligible tasks execute immediately through fresh constraint-bound grants and scoped executors.
8. Exact grants, requests, observations, budgets, evidence, costs, funnel facts, and timeline
   events are persisted.
9. Reproduced candidates enter the existing human-review queue. Human submission is mandatory.
10. Restart/resume uses the current durable scheduler and never repeats completed state-changing
    execution.

Policy, scope, approvals, controlled identities, backend readiness, and constraint enforceability
are rechecked immediately before grant issuance and execution. A stale decision is recomputed
against a fresh snapshot. Recomputed decisions append a new version; the historical decision and
grant governing earlier execution remain immutable evidence.

## Durability and Budget Semantics

Budget consumption is monotonic across restart and resume. Policy refresh or grant replacement
cannot reset consumed request, cost, concurrency-attempt, or elapsed-time budgets. Resume uses
persisted task completion and idempotency state. Prior grants are never silently reused after
freshness or authorization invalidation.

Required policy, scope, approval, identity, backend, or constraint failures fail closed with an
explicit decision status. Effectiveness-ledger unavailability degrades learning only if the
canonical hunting runtime remains healthy; no failed ledger write is reported as successful and
learned ranking receives no authority.

Campaign lifecycle distinguishes hunting execution from external program outcomes. Execution may
finish while submissions, triage, or bounty results remain unresolved. The completion state is
`EXECUTION_COMPLETE_OUTCOMES_PENDING` until all linked outcomes are terminal. Later outcome facts
append to the canonical ledger without rewriting campaign execution history.

## Initial Portfolio

The runner is generic. Initial operator manifests target GitLab and Atlassian separately, each
with a six-hour maximum duration, $10 maximum machine/API cost, current explicitly eligible
assets, policy-derived request/rate/concurrency limits, and operator-owned identities where
needed. Advertised reward ranges remain separate from candidate payout estimates.

No candidate source, including `reports/programs.json`, authorizes execution.

## Verification

Tests must cover:

- typed permission positive/negative controls and ambiguous-policy denial;
- asset/context isolation and approval scope/expiry;
- constraint-bound grant verification;
- unavailable, unsafe, and prerequisite-missing backend distinctions;
- stale-policy rejection, append-only recomputation, and fresh grant issuance;
- monotonic request, cost, attempt, concurrency, and time budgets across resume;
- restart without duplicate state-changing execution;
- canonical mission, evidence, review, cost, funnel, and shadow-ranking lineage;
- effectiveness-ledger outage without fake success or scheduler authority changes;
- end-to-end execution of a permissive technique through the canonical authority chain;
- `EXECUTION_COMPLETE_OUTCOMES_PENDING` and later outcome completion;
- mandatory human review and submission.

Production acceptance requires the full test suite, Ruff, PostgreSQL integration, benchmark, and
Self Hunt to remain green. No live campaign is authorized by this implementation or its fixtures.
