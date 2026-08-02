# Phase 1 — Execution Foundation and Safety Corrections

Status: design approved on 2026-08-02

## Objective

Create the durable, tenant-safe execution substrate required by every external
adapter. Phase 1 performs no new vulnerability scanning. Its completion proves
that fake adapters can be scheduled, scoped, reserved, cancelled, resumed,
audited, and normalized safely.

## Required corrections to the current code

### Tenant-bound authorization

Add `tenant_id` and an engagement-access policy to `ApiPrincipal`. Persist
`tenant_id` on engagements and all new scan records. Every engagement dependency
must load by `(tenant_id, engagement_id)`. Operators are tenant operators, not
global operators. A separately configured system-admin role is reserved for
operations and cannot execute scans.

Existing JSON API-key configuration remains supported through an explicit
single-tenant compatibility mode. Production readiness rejects compatibility
mode.

### Atomic policy reservations

Replace the authorize-then-commit race for executable work with a reservation
operation. A successful reservation records:

- the policy decision and immutable request;
- reserved spend, request allowance, and session slot;
- approval grants consumed by the reservation;
- an expiration time and idempotency key.

PostgreSQL uses a transaction and row locks. SQLite uses `BEGIN IMMEDIATE`.
Finalization records actual consumption and releases the remainder. Cancellation
or expiration releases unused resources. A reservation is finalized at most
once. The existing decision endpoint remains available for non-executing dry
runs and compatibility.

### Trusted scope and detector actions

Add one scope resolver that reads the stored authorization snapshot. Reporting,
scheduling, normalization, and network execution all call this resolver.

`DetectorWorker` creates a request context per detector and uses
`detector.action`, not the outer planned action. The detector registry validates
that names, actions, and capability tiers are unique and known. BFLA requires an
existing low-privilege identity, an elevated baseline or a mandatory response
signature, and a differential result before emitting a candidate.

### Documentation corrections

Update production and roadmap claims so “automatic recon-to-BOLA,” production
durability, and HA are described according to tested behavior. The stale
production TL;DR must not contradict later sections.

## New domain model

`ScanRun` stores tenant, engagement, authorization/scope digest, configuration
hash, status, timestamps, and the immutable adapter manifest set.

`StageRun` stores the stage type, dependency set, input hash, status, and retry
policy.

`TaskRun` stores target, adapter, capability tier, quotas, idempotency key,
status, and result summary.

`TaskLease` stores owner, heartbeat, expiration, and cancellation state.

`PolicyReservation` stores decision, reserved limits, actual usage, expiration,
and terminal status.

`Artifact` stores metadata, classification state, checksum, encrypted storage
reference, size, and retention deadline. Raw bytes are not stored in general
database columns.

The existing engagement repository is not expanded into an unbounded interface.
Introduce focused repository protocols for scans, leases, reservations,
artifacts, and observations, composed by a repository bundle. SQLite and
PostgreSQL implement the same behavioral contract.

## Schema management

Introduce ordered, checksum-verified SQL migrations. Startup applies compatible
forward migrations under a database lock and refuses an unknown or downgraded
schema. SQLite and PostgreSQL may use engine-specific SQL files but must expose
the same logical schema version and repository tests.

## Adapter contract

`AdapterManifest` contains name, semantic version, executable/container digest,
license identifier, capability tier, input schema version, output schema
version, and network profile.

`ExecutionEnvelope` contains the immutable fields defined by the master design.

`AdapterEvent` is a discriminated union for asset, service, route, parameter,
technology, secret candidate, diagnostic, progress, and terminal events. Events
include source, observed time, target, task, adapter version, confidence, and
raw-artifact reference.

Adapters implement manifest validation, command construction, line parsing, and
terminal-result interpretation. They do not receive repository objects.

## Safe process runner

- Execute argument arrays without a shell.
- Use a minimal allowlisted environment and an isolated working directory.
- Resolve secret references into protected files or input streams, not argv.
- Verify binary version and checksum before each new worker image is accepted.
- Bound wall time, idle time, stdout/stderr bytes, line length, event count,
  memory, CPU, open files, and child processes.
- Stream output; never buffer unbounded process output.
- On cancellation, terminate the complete process tree and wait for cleanup.
- Classify exit codes and malformed output without trusting stderr text.

## Scoped execution gateway

Provide a testable gateway interface and a fake enforcement backend in Phase 1.
The production backend must enforce network namespace/container egress rules,
not merely proxy environment variables. It supports the network profiles in the
master design, DNS pinning, redirect revalidation, request budgets, and network
audit events.

Phase 1 can ship with real external adapters disabled until the production
backend proves direct-egress denial.

## Scheduler and recovery

The coordinator creates a stage DAG, queues dependency-ready tasks, and leases
tasks with compare-and-set semantics. Workers heartbeat leases. Lease expiry can
requeue only tasks whose retry policy and idempotency permit it.

Kill-switch activation changes queued work to `cancelled`, signals active
leases, terminates process trees, and prevents new claims. Invalid output or a
sensitive-data signal changes the task to `quarantined`.

## API surface

Add tenant-scoped endpoints to create/list/read/cancel scans and inspect stages,
tasks, and sanitized artifacts. Task leasing and heartbeat endpoints require a
worker principal. Raw artifact access requires an operator plus an explicit
quarantine-review action; it is not exposed through normal scan responses.

## Tests

- Tenant-crossing requests are denied for agents and operators.
- Concurrent reservations cannot exceed spend or session capacity.
- Duplicate finalization and concurrent commits are idempotent.
- Single-use approvals are consumed atomically with a reservation.
- Fake process runner tests cover timeout, output flood, malformed JSONL,
  cancellation, child cleanup, and secret non-disclosure.
- Gateway tests cover direct-egress denial, redirects, private IPs, mixed DNS,
  DNS changes, provider allowlists, and quota exhaustion.
- SQLite/PostgreSQL repository contract and migration tests pass.
- Crash/restart tests reclaim leases and preserve successful task state.
- Report scope cannot be overridden by API input.
- Detector requests use detector-specific actions.

## Completion gate

Phase 1 is complete when a fake discovery adapter can run through the real API,
reservation, lease, process, event, quarantine, normalization, persistence, and
cancel/resume paths on SQLite and PostgreSQL, with no direct network access and
all tests above passing.

