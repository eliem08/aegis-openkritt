# Hardened Single-Server Production Deployment

Status: approved on 2026-08-03

## Objective

Turn the current development Compose stack into a reproducible, production-like
single-server deployment suitable for supervised, authorized bug-bounty work.
The deployment must prove the existing safety contracts across real service and
process boundaries. It is a stepping stone to the distributed topology described
in the Phase 5 design, not a claim of high availability.

## Scope and safety boundary

The deployment may scan only targets covered by an active signed authorization.
All automated end-to-end tests use local synthetic vulnerable targets. No public
bug-bounty target is contacted by test or drill automation.

The production profile fails closed when authorization, coordination, database,
gateway, secrets, browser, scanner pinning, or OAST validation is unavailable.
Unattended exploitation and automatic report submission remain out of scope.

## Deployment layout

Keep `docker-compose.yml` as the local development stack and add an explicit
production Compose project. The production project contains:

- a control-plane API with no direct target-facing internet route;
- PostgreSQL as durable state;
- Redis as ephemeral coordination;
- a scoped egress proxy attached to both an internal worker network and a
  dedicated egress network;
- capability-specific scanner and browser workers attached only to internal
  networks;
- a private OAST service reachable only through its declared network profile;
- local authorized lab targets in a separate, opt-in test profile;
- one-shot migration, readiness, backup, restore, and drill containers.

Workers cannot obtain an external route from their network namespace. Target
traffic must traverse the egress proxy. Proxy environment variables alone do not
count as enforcement. Containers run non-root, drop Linux capabilities, use
read-only root filesystems where possible, bound memory/CPU/PID limits, and mount
only task-scoped writable storage.

## Configuration and secrets

Development defaults are forbidden in the production project. A bootstrap tool
creates high-entropy local secrets into a git-ignored directory with restrictive
permissions. Services consume mounted secret files; secret values are not placed
in Compose YAML, images, command lines, or committed `.env` files.

Required secrets include PostgreSQL and Redis credentials, tenant-bound API keys,
authorization signing keys, encryption keys, gateway service credentials, and
OAST credentials. The readiness check reports only secret names and validation
errors, never values.

Local single-server encryption uses versioned file-mounted keys. Cloud KMS/HSM or
Vault integration remains a distributed-production requirement.

## PostgreSQL

PostgreSQL uses a pinned image digest, authenticated encrypted connections,
persistent storage, bounded connections, schema migrations, and health checks.
The application uses the existing PostgreSQL repositories rather than in-memory
fallbacks when the production profile is active.

Backup and restore scripts create timestamped encrypted logical backups, verify
checksums, restore into an isolated verification database, run migrations and
integrity checks, and produce a machine-readable drill result. A failed backup or
unverified restore cannot be reported as successful.

This design validates restart and restore recovery on one host. Replication,
automatic failover, and point-in-time recovery remain future infrastructure work.

## Redis coordination

Add a real Redis backend behind the existing coordinator interface. Operations
for rate windows, expiring semaphore membership, cancellation broadcasts, and
deduplication are atomic. Keys are namespaced by deployment and tenant. Redis is
authenticated, private, persistent only where useful, and has bounded memory.

Loss of Redis denies new active work, pauses eligible passive work, and causes
running workers to honor cancellation uncertainty. Recovery reconciles ephemeral
semaphores from durable PostgreSQL leases without changing reservations.

## Scoped egress

The egress proxy is the only container with an external route. It accepts a
short-lived, signed request authorization containing tenant, engagement, network
profile, method, destination, expiry, and request-budget identity. It verifies the
authorization and calls the existing scope policy before resolving or connecting.

The proxy performs private-address denial, DNS pinning, redirect revalidation,
method filtering, request-budget accounting, and structured audit logging. It
does not expose a general-purpose open proxy. Scanner binaries that cannot use the
proxy are unsupported and fail closed in this deployment.

Tests prove that worker containers cannot connect directly to an external or lab
target address, while an authorized request through the proxy succeeds and an
out-of-scope, private-address, expired-token, or over-budget request fails.

## Scanner and browser workers

Every scanner release is recorded in a lock manifest with source, version,
license-review status, executable checksum, image digest, and output schema. A
worker refuses an absent, mutable, unreviewed, or mismatched entry.

The browser worker uses a pinned Chromium/Playwright image and the same scoped
egress route. Downloads, extensions, arbitrary executable launch, and persistent
browser profiles are disabled. Browser artifacts pass through the sensitive-data
classifier before persistence.

## Private OAST

The OAST service is privately operated and configured with a user-provided domain
and TLS certificate. Startup rejects known public OAST domains. Correlation tokens
are engagement-bound, unpredictable, expiring, and stored encrypted. Teardown
revokes registrations and retention removes expired callback data.

Because a routable domain and certificate cannot be manufactured safely by the
repository, the deployment provides configuration validation and a disabled-by-
default Compose profile. The production readiness gate remains red until a real
private endpoint passes registration, callback, expiry, and teardown tests.

## Operational drills

One command runs non-destructive drills against the local authorized lab and
emits JSON plus a Markdown report. It covers:

- migrations and PostgreSQL restart;
- backup, isolated restore, and integrity verification;
- Redis outage, fail-closed admission, recovery, and reconciliation;
- worker direct-egress denial and scoped-proxy allow/deny behavior;
- scanner checksum mismatch refusal;
- browser scope enforcement and artifact quarantine;
- private OAST lifecycle when its profile is configured;
- API authentication and tenant isolation;
- kill-switch propagation during bounded lab traffic;
- bounded smoke load with latency and error summaries.

Skipped infrastructure-dependent checks are failures for a production verdict,
not silent passes. The report distinguishes `pass`, `fail`, and `not_configured`.

## Documentation and operator experience

Update `PRODUCTION.md`, the implementation ledger, and the runbook so claims match
the executable deployment. Document bootstrap, start, readiness, drills, backup,
restore, rotation, shutdown, log collection, and recovery. Clearly label the
development stack, hardened single-server stack, and future HA topology.

## Acceptance criteria

The implementation is complete when:

1. Existing unit tests remain green.
2. Real PostgreSQL and Redis integration tests pass against the Compose stack.
3. A production configuration cannot fall back to memory, SQLite, fake Redis,
   fake browser execution, unpinned scanners, public OAST, or direct worker egress.
4. The authorized local-lab end-to-end flow produces a tenant-scoped finding and
   report through the real service boundaries.
5. Backup/restore, Redis outage/recovery, kill-switch, and egress-isolation drills
   pass and generate reviewable artifacts.
6. Production-readiness validation lists every unmet external prerequisite and
   returns non-zero until all required gates pass.
7. No secret is committed or printed, and repository secret scanning passes.

Passing this gate means the project is suitable for a supervised single-server
pilot. It does not establish multi-node HA, cloud KMS protection, or proven bounty
revenue.
