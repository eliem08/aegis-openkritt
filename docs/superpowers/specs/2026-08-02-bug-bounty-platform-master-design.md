# Aegis Bug-Bounty Platform — Master Design

Status: approved in conversation on 2026-08-02

## Purpose

Turn Aegis from a strong policy/control-plane prototype into a supervised,
production-capable bug-bounty research platform. Aegis will reuse the proven
operating patterns of eleven established open-source tools while keeping policy,
scope, evidence, orchestration, and product data inside the proprietary Aegis
control plane.

This document is the program-level architecture. Each implementation phase has
its own design specification in this directory. The live mapping from reference
repositories to Aegis work lives in `docs/REPO_STRENGTHS_IMPLEMENTATION.md`.

## Verified starting point

The design is based on the checkout at commit `57a0b56`. At approval time:

- 331 tests pass; three PostgreSQL integration tests are skipped without a DSN.
- The deterministic policy engine, control-plane API, signed authorizations,
  kill switch, approvals, HTTP scope transport, orchestrator, detectors,
  reporting, SQLite/PostgreSQL repositories, Fernet encryption, and Ed25519
  verification exist.
- PostgreSQL persists engagements, approvals, audit events, kill state, and
  spend. It does not persist scan jobs, tasks, assets, observations, or artifacts.
- Recon-to-BOLA is a helper demonstrated by a test, not an orchestrator stage.
- External binaries do not yet have an enforceable network sandbox.
- Authorization and budget debit are separate operations and can overbook under
  concurrency. API principals are role-based but not tenant-bound.
- Report scope is supplied by the caller, and detector requests inherit one
  outer action rather than the detector's declared action.

## Product goals

1. Discover and continuously map authorized attack surfaces with provenance.
2. Run bounded, policy-gated active tests with researcher-owned accounts and
   synthetic canaries.
3. Produce reproducible, redacted, non-duplicate, human-reviewed reports.
4. Resume safely after restarts and worker failures without repeating intrusive
   work or exceeding budgets.
5. Scale from one supervised workstation to a tenant-isolated worker fleet.
6. Preserve clear license boundaries and a replaceable adapter architecture.

## Non-goals

- Unattended exploitation or automatic vulnerability submission.
- Testing outside a signed authorization or a program's written rules.
- Accessing real users' private data to prove impact.
- Copying AGPL/GPL implementation code into proprietary Aegis.
- Recreating every feature of the reference tools.
- Adding a patch/PR automation protocol in this program; it remains separate.

## Chosen approach

Use a hybrid control plane:

- Aegis-native: authorization, scope, reservations, scheduling, task leases,
  asset graph, provenance, evidence, sensitive-data controls, diffs, and reports.
- Pinned adapters: maintained MIT-licensed tools whose machine output can be
  normalized behind stable interfaces.
- Clean-room behavior: useful patterns from AGPL/GPL projects, implemented from
  the behavior specification without copying source or restricted datasets.
- Optional separately installed tools: permitted only when their license and
  deployment model have been reviewed for the intended distribution.

## System architecture

```text
Program ingestion / operator input
              |
      Signed authorization
              |
        Control-plane API
              |
    Policy + reservation service
              |
        Durable scan scheduler
              |
     Leased stage/task execution
              |
   Scoped execution gateway -------- Private OAST service
              |
       Pinned tool adapters
              |
      Bounded adapter events
              |
   Quarantine + sensitive-data gate
              |
  Normalizer + provenance asset graph
              |
   Detection / evidence / triage
              |
  Human-reviewed submission package
```

### Core boundaries

`ScanCoordinator` owns stage dependencies and state transitions. It never parses
tool-specific output.

`ToolAdapter` translates an immutable execution envelope into a safe process
invocation and translates output into typed events. It never writes product
state directly.

`ScopedExecutionGateway` is the only network route available to target-facing
tools. It validates signed scope, DNS-pins approved destinations, rechecks
redirects, rate-limits requests, and records network audit events.

`ObservationNormalizer` validates, deduplicates, and stores adapter events. Raw
output remains quarantined until classification and schema checks pass.

`AssetGraph` stores durable assets and immutable observations. A current asset
view is derived from observations; historical facts are not overwritten.

`EvidencePipeline` turns verified detector observations into redacted evidence,
findings, quality-gate results, and reports. It derives scope from the stored
signed authorization instead of accepting a caller-provided boolean.

## Execution envelope

Every task receives an immutable envelope with:

- tenant, engagement, scan, stage, and task identifiers;
- target and signed-scope digest;
- adapter name, version, checksum, license, and capability tier;
- allowed network profile and approved external service identifiers;
- request, concurrency, time, output-byte, and monetary limits;
- credential references, never credential values;
- configuration and input hashes;
- deadline, cancellation token, and idempotency key.

Workers reject incomplete envelopes. Adapters may reduce capabilities or limits
but cannot widen them.

## Network profiles

`passive-provider` permits only configured intelligence-provider endpoints and
does not permit direct target traffic.

`target-observation` permits DNS-pinned signed-scope targets with safe HTTP
methods and a strict request budget.

`target-mutation` permits only the approved target, methods, detector action,
and payload family recorded in the reservation.

`private-oast` adds the private Aegis Interactsh endpoint to the approved target
profile. Public OAST services are disabled by default.

Containers receive no direct egress. Proxy environment variables alone are not
considered enforcement; the runtime/network namespace must deny bypass traffic.

## Durable state and idempotency

The durable model contains `ScanRun`, `StageRun`, `TaskRun`, `TaskLease`,
`PolicyReservation`, `Artifact`, `Asset`, `Observation`, `AssetSnapshot`,
`OastSession`, and `NotificationDelivery` records.

Task idempotency is keyed by `(scan, stage, target, adapter version, input hash)`.
Only one live lease may own a key. Reclaimed work resumes from the last completed
idempotent boundary. State-changing work is never retried automatically.

Task states are `queued`, `leased`, `running`, `succeeded`, `retryable_failed`,
`blocked`, `cancelled`, and `quarantined`. Invalid transitions fail closed and
produce audit events.

## Security invariants

1. Signed scope is immutable for a scan.
2. Tenant and engagement access is checked on every control-plane operation.
3. Policy approval and resource reservation occur atomically before execution.
4. A detector is gated using its own declared action and capability tier.
5. Kill-switch activation blocks new leases and terminates active process trees.
6. Secrets are referenced, injected at runtime, and excluded from arguments,
   logs, events, and persisted envelopes.
7. Raw output cannot enter the asset graph before schema, scope, and
   sensitive-data checks pass.
8. Report scope and rules compliance are derived from stored authorization.
9. No finding is submittable without reproducibility, verification, material
   impact, redaction, scope, and duplicate gates.
10. Submission is always a human action.

## Phase order

1. Foundation and safety corrections.
2. Passive discovery and observation adapters.
3. Guarded active testing and clean-room discovery algorithms.
4. Private OAST, browser workflows, monitoring, and sensitive-data controls.
5. Distributed production scale and operational hardening.

Phases are dependency-ordered. Code for a later phase may be merged behind a
disabled feature flag, but it cannot be enabled until all earlier phase
acceptance suites pass.

## Licensing boundary

Subfinder, httpx, Katana, gau, jsluice, Nuclei, Dalfox, and Interactsh are used
through adapters subject to version-specific license verification and retained
notices. Arjun and Kiterunner are behavioral references for clean-room
implementations because their audited versions are AGPL-3.0. reNgine is a
behavioral architecture reference because its audited version is GPL-3.0.

The delivery ledger records the audited version, license, integration strategy,
and implementing commit. This is an engineering policy, not legal advice; a
distribution-specific legal review remains required before shipping binaries.

## Program-level acceptance criteria

- Every adapter has contract, parser, cancellation, output-limit, and network
  escape tests.
- Every active request is traceable to a signed authorization and reservation.
- Concurrent authorization cannot exceed spend, request, or session limits.
- Worker crashes and control-plane restarts do not lose completed observations
  or repeat non-idempotent work.
- A target outside the immutable scope cannot be reached by Python or an
  external tool, including through DNS rebinding or redirects.
- Sensitive artifacts are quarantined and never rendered into reports.
- The repository-strength ledger contains no undocumented enabled capability.
- The full default suite and all enabled integration suites pass at release.

## Deliverables

- The five phase specifications beside this document.
- `docs/REPO_STRENGTHS_IMPLEMENTATION.md` as the live implementation ledger.
- Separately reviewable implementation plans and commits per phase.
- Updated production documentation only when acceptance tests prove the claim.

