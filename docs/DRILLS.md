# Hardened production drills

The drill runner records `pass`, `fail`, or `not_configured`. Every required gate
must be `pass` for a production verdict; missing infrastructure is never a skip.

## Live hardened-service evidence (2026-08-03)

Using the locally cached official registry digests for PostgreSQL 16 Alpine and
Redis 7 Alpine:

- both custom images built and reached healthy state;
- PostgreSQL created the intended `aegis` database, accepted a
  `sslmode=verify-full` connection, reported `ssl=true`, and had zero
  `trust` HBA rules after bootstrap;
- Redis required its generated password and returned `PONG`;
- Docker reported no host-published ports for either service;
- a forced Redis snapshot plus PostgreSQL committed row both survived container
  restart; the drill key/table were removed afterward;
- the application image built from the official immutable Python 3.12-slim
  manifest digest.

The first live attempt correctly failed: Redis referenced unavailable `su-exec`,
and PostgreSQL peer auth prevented creation of the service-owned database.
Those entrypoint defects were fixed and regression tests were added. Worker
direct-egress, browser, scanner, OAST, backup/restore, and failure-injection drills
remain pending their real approved inputs.

## Code-backed and tested

The repository test suite covers:

- atomic Redis rate windows, semaphores, deduplication, expiry, namespacing, and
  fail-closed outage behavior;
- signed egress authorization, destination/method binding, scope/private-IP
  denial, redirect reauthorization, response limits, and global request budgets;
- production configuration and `_FILE` secret inputs;
- release-lock schema, immutable images, legal-review flags, and executable
  checksum tamper rejection;
- secret/TLS bootstrap without secret disclosure or accidental overwrite;
- chunk-authenticated encrypted backup round trips and tamper rejection;
- strictly bounded disposable restore-database names;
- drill verdicts that reject both failure and missing configuration.

## Live single-server sequence

Run these only against the hardened stack and local/authorized targets:

1. Start the production stack and confirm PostgreSQL, Redis, egress, and control
   plane health.
2. Run `production-drills`; retain its JSON and Markdown output.
3. Stop Redis. Confirm new active work is denied, passive work pauses, and running
   work treats cancellation as active. Restart Redis and reconcile durable leases.
4. Start the opt-in authorized lab. From a worker-only container, prove direct
   target connectivity is impossible. Then run an authorized request through the
   signed egress boundary and prove out-of-scope/private/expired/over-budget
   requests fail.
5. Create an encrypted backup, verify its archive, restore it into the generated
   `aegis_verify_*` database, validate migrations/tables, and confirm the
   verification database was removed.
6. Start the digest-pinned browser worker, execute the authorized lab workflow,
   and confirm downloads are quarantined and out-of-scope browser events blocked.
7. Register a private OAST session, observe a lab callback, reject an unmatched
   callback, expire and deregister the session, then verify retention cleanup.
8. Fire the kill switch during bounded lab traffic and confirm queued work drains
   and no new lease is granted.
9. Run bounded load, record latency/error summaries, and set alerts from evidence.

## Historical evidence

Earlier development-stack drills passed PostgreSQL restart durability,
`pg_dump`/`pg_restore`, reservation idempotency, stale-lease reclaim, concurrent
budget admission, and kill-switch behavior. Those results remain useful regression
evidence but do not substitute for the hardened Compose gate.

## Not covered by a single-server drill

Replication promotion, point-in-time recovery, multi-node Redis failover,
KMS/HSM/Vault rotation, rolling upgrades, and production-scale SLO validation
require the future distributed deployment. They remain blocked until real
infrastructure and operator evidence exist.
