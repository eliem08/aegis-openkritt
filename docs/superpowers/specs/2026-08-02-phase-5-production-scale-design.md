# Phase 5 — Distributed Production Scale

Status: design approved on 2026-08-02

## Objective

Harden the validated single-site system for tenant-isolated distributed workers,
high availability, operational recovery, and controlled upgrades.

## Distributed coordination

Use PostgreSQL as durable product state and Redis as ephemeral coordination for
distributed rate buckets, concurrency semaphores, lease heartbeats, cancellation
broadcasts, and short-lived deduplication. PostgreSQL remains the source of truth
for task and reservation terminal states.

Redis loss must fail closed for new active work. Passive-provider tasks may be
configured to pause rather than fail. Reconciliation restores coordination from
durable leases without double-finalizing reservations.

Workers claim typed queues by capability. A browser worker cannot claim OAST or
template tasks unless its signed worker identity declares those capabilities.
Worker credentials are short-lived and mutually authenticated.

## PostgreSQL production topology

- Managed or operator-supported replication, automated failover, encrypted
  connections, point-in-time recovery, and tested backups.
- Connection-pool sizing per service and bounded transaction duration.
- Online-compatible migrations with forward/backward application windows.
- Foreign keys, tenant-leading indexes, retention partitions, and query budgets.
- Restore drills that verify encrypted records and task/reservation consistency.

SQLite remains a supervised single-node option and is not advertised as HA.

## Key and secret management

Replace production `.env` secrets with a cloud KMS/HSM or Vault-like service.
Support versioned key identifiers, overlapping Ed25519 verification keys, Fernet
data-key envelopes or equivalent authenticated encryption, rotation jobs, and
audited revocation.

Existing ciphertext receives a key identifier. Rotation can rewrap data without
making it unavailable. A missing or revoked key fails closed with a diagnostic;
it never falls back to plaintext.

## Isolation and supply chain

- Run each adapter in a minimal non-root image with a read-only root filesystem,
  temporary writable workspace, seccomp/capability restrictions, resource limits,
  and enforced network profile.
- Pin images by digest and verify executable/template checksums.
- Generate SBOMs and retain upstream license notices.
- Scan dependencies and images; block releases above the configured severity
  policy unless an operator records a time-limited exception.
- Use signed build provenance and a canary environment before production rollout.

## Observability and SLOs

Instrument API, scheduler, gateway, adapters, repositories, OAST, browser, and
notification paths with OpenTelemetry-compatible traces, metrics, and structured
logs. Tenant identifiers are pseudonymous in general telemetry.

Track at minimum:

- policy/reservation latency and denial reasons;
- queued/leased/running age and lease expiry;
- request rate, gateway blocks, retries, and target health;
- adapter version/error/output-schema rates;
- sensitive-data quarantines;
- snapshot coverage and finding verification rates;
- notification delivery and report quality-gate failures.

Initial release SLOs are defined from load-test evidence, not invented targets.
The deployment cannot be declared production-ready without alert thresholds and
on-call actions for every critical failure mode.

## API and operational protection

Add short-lived service identities, tenant quotas, request-body limits, API rate
limits, pagination caps, audit export controls, administrative break-glass
procedures, and immutable security event retention. System administration and
tenant operations remain separate roles.

## Deployment and recovery

Provide production manifests or modules for the selected runtime, separate
control/data planes, private service networking, TLS, secrets integration,
database/Redis dependencies, autoscaling bounds, disruption budgets, and staged
rollouts.

Run failure drills for worker death, gateway failure, Redis loss, PostgreSQL
failover, stale leases, key unavailability, OAST outage, partial deployment, and
kill-switch activation. Recovery must preserve scope, reservations, evidence
quarantine, and idempotency.

## Tests

- Multi-worker race tests for leases, reservations, approvals, and cancellation.
- Redis outage/recovery and PostgreSQL failover/restart tests.
- Tenant-isolation tests across APIs, queues, storage, telemetry, and artifacts.
- Key rotation, revocation, backup, restore, and wrong-key tests.
- Image direct-egress, privilege, filesystem, checksum, and SBOM policy tests.
- Load tests using a local synthetic lab, never public bug-bounty targets.
- Rolling-upgrade compatibility and rollback drills.
- End-to-end kill-switch propagation under load.

## Completion gate

Phase 5 is complete only after the deployment passes load, isolation, failover,
restore, rotation, supply-chain, and kill-switch drills with documented operator
runbooks. This gate permits a supervised production launch; it does not permit
unattended exploitation or automatic submission.

