# Production readiness

This document distinguishes implemented controls from infrastructure that has
actually passed a live drill. A configuration value or test double is not a
production result.

## Current verdict

The deterministic policy, authorization, tenancy, budget, reservation, evidence,
detector, reporting, and persistence layers are suitable for supervised use. The
repository now also contains a hardened single-server deployment with real
PostgreSQL and Redis paths, signed scoped egress, file-mounted secrets, runtime
release pins, encrypted backups, isolated restore verification, and executable
readiness reports.

The stack is **partially live-verified on this machine**. The digest-pinned
PostgreSQL and Redis images built and started successfully; authenticated
verify-full PostgreSQL TLS, zero remaining trust rules, authenticated Redis,
unpublished host ports, health checks, and restart persistence all passed. The
digest-pinned application image also built successfully. The full stack remains
blocked because the repository deliberately does not invent scanner/browser
release approvals, a private OAST domain, or its certificate. Until those gates
pass, use the development stack or an authorized supervised lab; do not claim
unattended production readiness.

## Implemented production boundaries

- `aegis.production` is a production-only entrypoint. It rejects missing
  PostgreSQL, authenticated Redis, file-mounted secrets, egress enforcement,
  private OAST, and digest-pinned scanner/browser configuration.
- PostgreSQL stores control-plane state, scans, graph data, learning outcomes,
  and HackerOne submission links. Production does not retain the SQLite learning
  fallback.
- Redis uses atomic Lua operations for rate windows and semaphore admission.
  Coordination loss denies active work, pauses eligible passive work, and assumes
  cancellation.
- Worker networks are internal-only. The scoped egress service is the sole
  dual-homed service and accepts only short-lived signed HTTP authorizations.
- Egress rechecks scope, methods, DNS/private addresses, redirects, and a global
  Redis-backed request budget. It is not a general CONNECT proxy.
- Scanner releases require an approved lock entry containing an executable hash,
  immutable image digest, schema, and license-review result. Runtime startup can
  verify the installed executable bytes.
- Browser and infrastructure images are supplied by immutable digest. A pin alone
  does not pass the browser drill; Chromium must run in the isolated worker image.
- Private OAST rejects known public providers. Its gate remains incomplete until a
  real private endpoint passes health, registration, callback, expiry, and teardown.
- Secret bootstrap generates independent API, signing, encryption, backup,
  database, Redis, gateway, and PostgreSQL TLS material without printing values.
- Backups are chunk-authenticated and checksummed. Restore verification is allowed
  only into a disposable `aegis_verify_*` database, validates migrations/tables,
  and removes that database afterward.

## Development versus production

`docker-compose.yml` remains local development only. It uses development database
credentials and must never be presented as hardened deployment evidence.

The production deployment is composed from:

- `compose.production.yml` — PostgreSQL, Redis, control plane, scoped egress, and
  the opt-in authorized lab;
- `compose.production.ops.yml` — encrypted backup, archive verification, and
  production-gate report jobs;
- `compose.production.restore.yml` — disposable database restore drill.

## Bootstrap

Install the production Python dependencies locally, then create ignored secret
files:

```bash
python -m aegis.production.bootstrap
cp production.env.example secrets/production.env
```

The bootstrap creates `secrets/scanner-releases.lock.json` with an empty release
list. That is intentional: populate it only after reviewing the exact release,
license, publisher checksum/signature, executable path, immutable image digest,
and output schema.

Replace every `REPLACE_WITH_64_HEX_DIGEST` value in
`secrets/production.env`. Configure a privately controlled OAST domain. Do not use
a public shared OAST provider.

## Start

```bash
docker compose --env-file secrets/production.env \
  -f compose.production.yml up --build -d
```

The control plane binds to loopback by default. Put a reviewed TLS reverse proxy
in front only when remote operator access is required.

## Backup and recovery

```bash
docker compose --env-file secrets/production.env \
  -f compose.production.yml -f compose.production.ops.yml \
  --profile ops run --rm backup

docker compose --env-file secrets/production.env \
  -f compose.production.yml -f compose.production.ops.yml \
  --profile ops run --rm verify-backup

docker compose --env-file secrets/production.env \
  -f compose.production.yml -f compose.production.ops.yml \
  -f compose.production.restore.yml \
  --profile ops run --rm restore-drill
```

Backups and reports are written to ignored `backups/` and `drill-reports/`
directories. Preserve them outside the host after reviewing access controls.

## Production gate

```bash
docker compose --env-file secrets/production.env \
  -f compose.production.yml -f compose.production.ops.yml \
  --profile drills run --rm production-drills
```

The command exits non-zero when a required check is `fail` or `not_configured`.
It produces JSON and Markdown reports. Skips never count as production passes.

## Still external or unproven

- Full worker/browser image builds and container-level direct-egress denial on the selected host.
- Live approved scanner binaries and their legal/license review.
- Chromium running a scoped workflow through the isolated browser boundary.
- A real privately operated OAST endpoint and callback lifecycle.
- Sustained load evidence and derived alert/SLO thresholds.
- PostgreSQL replication/failover/PITR, Redis failover, and rolling upgrades.
- Cloud KMS/HSM/Vault key custody and live rotation.
- Real bug-bounty payout evidence. The software can support revenue; it cannot
  guarantee a valid finding or payment.

Passing the single-server gate permits a **human-supervised authorized pilot**.
It never permits unattended exploitation or automatic report submission.
