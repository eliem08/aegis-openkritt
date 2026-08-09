# Universal Profit Jarvis — canonical consolidation

## Decision

Consolidate the existing Aegis runtime instead of creating a parallel Jarvis. The canonical
flow is:

`authorized asset -> HuntOpportunity -> portfolio allocation -> MissionPlan -> PolicyEngine -> signed ExecutionGrant -> capability worker -> canonical evidence -> FindingLifecycle -> HumanApprovalReceipt -> outcome learning`.

## Canonical contracts

- Extend the existing scheduler opportunity/economics contract into a cross-asset
  `HuntOpportunity`. Preserve unknown bounty as `None`; expose gross value, decomposed costs,
  net value, uncertainty, provenance, scope and authorization identity.
- Extend the existing Jarvis `MissionPlan` and `MissionTask`. Every mission references one
  opportunity and every task declares capability, risk, prerequisites, cost/request bounds,
  evidence/success/failure criteria and an explicit durable state.
- Keep `PolicyEngine -> PolicyDecision -> signed ExecutionGrant -> executor` as the only
  active authority chain. Jarvis agents only propose work.

## Runtime integration

- Normalize all structured program assets conservatively and persist graph edges with
  provenance, confidence, timestamp and authorization context.
- Generate only surface-compatible opportunities and rank them with the existing profit
  kernel, saturation signals, coverage gaps, change state and bounded exploration.
- Adapt the repository hunter to produce source-code opportunities and consume universal
  missions. It must not remain a separate production execution path.
- Match tasks through the existing capability registry. Offline tools require execution
  tickets and the networkless sandbox; scoped network/dynamic work requires a verified grant.
- Reuse existing SQLite/Postgres leases, heartbeats, retries and recovery for 24/7 execution.
- Persist explicit `WAITING_FOR_PREREQUISITE` and `UNAVAILABLE` results; planning is never
  reported as execution.

## Proof

- Add a canonical synthetic multi-asset integration test covering repository, API, APK and
  smart-contract assets through selection, mission compilation, authorization, safe execution,
  evidence, lifecycle, signed human approval, payout ingestion and changed next-round priors.
- Add fail-closed tests for scope, expiry, forged grants, unavailable sandbox/scanners,
  lifecycle evidence/approval, negative EV, duplicate pressure and unchanged assets.
- Continuously run focused tests, then the full suite, Ruff, synthetic benchmark and configured
  real-CVE cases. Unavailable scanners are reported separately from misses; skipped cases never
  count as detections.

## Compatibility and migration

Existing public call sites remain supported through adapters during migration. Duplicate
production paths are deprecated only after the connected runtime and end-to-end tests prove
replacement behavior.
