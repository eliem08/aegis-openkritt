# Phase 5 Failure Drills — Runbook and Status

The Phase 5 completion gate requires load, isolation, failover, restore, rotation,
supply-chain, and kill-switch drills. Drills split into two groups: those runnable
against the local single-node stack (run and recorded here), and those that need
real production infrastructure (HA Postgres, Redis, KMS, a load harness) which is
**not** provisioned in this environment. Nothing below is claimed unless it was
actually executed.

## Runnable locally — EXECUTED, results recorded

**Live against the compose Postgres** (`scratchpad/drill_pg.py`,
`scratchpad/drill_restore.py`), latest run 2026-08-03:

| Drill | Result | Evidence |
|---|---|---|
| Durability + reconnect across a DB **restart** | **PASS** | state survived `docker restart`; fresh pool reconnected (`task=queued`, `spend=5.0`) |
| Stale-lease reclaim after a **crashed worker** | **PASS** | expired lease on a `running` task reclaimed → requeued |
| **Idempotent** reservation finalize (no double-commit) | **PASS** | repeat finalize left usage unchanged |
| **Backup / restore** (`pg_dump -Fc` → wipe → `pg_restore --clean`) | **PASS** | 26 KB dump; data wiped then fully restored & consistent (`task=queued`, `spend=7.5`, `rc=0`) |

**In-process, CI-covered drills** (`tests/tools/test_drills.py` — real threads/logic):

| Drill | Result |
|---|---|
| **Redis outage** fails closed (active DENY, passive PAUSE, cancellation assumed) + reconciles from durable leases on recovery | **PASS** |
| **Load**: 80 concurrent reservations against a cap of 10 → exactly 10 win, no overbooking | **PASS** |
| **Kill switch under load**: fires mid-scan → queued work drained, no new claims | **PASS** |

Plus the broader suite: multi-worker lease/reservation/approval races
(`test_reservations.py`, 20 racing threads), tenant isolation across API/queues/
artifacts, key rotation/revocation/wrong-key fail-closed (`test_keyring.py`),
supply-chain severity/image-pin policy (`tests/supply/`), and binary pinning +
tamper rejection (`tests/tools/test_pin.py`).

## Still NOT runnable here — genuinely require real infrastructure (blocked, not faked)

| Drill | Needs | Why not here |
|---|---|---|
| PostgreSQL **failover** (primary → replica promotion) | A replicated PG cluster with automated failover | Local compose is single-node; a restart (done above) is recovery, not failover |
| **KMS/HSM/Vault** live rotation against a real key service | A cloud KMS/Vault | The key-ring rotation/revocation mechanism is tested; live KMS integration is a deployment step |
| **Load at production scale** with SLO derivation | A load harness + the lab at scale | The concurrency-safety load drill runs above; deriving published SLOs needs sustained load-test evidence, not invented targets |
| Minimal non-root **seccomp images** + image egress/privilege/filesystem | Built container images + a runtime | Images are a deployment artifact; the SBOM/severity/pin policy is tested, the images are not built here |
| Rolling-upgrade / rollback | A deployment target | No deployment target |

## To run the full gate

1. Provision the production topology (HA Postgres, Redis, KMS, deployed control/data
   planes) per the Phase 5 spec.
2. Pin binaries with `python -m aegis.tools.pin <release-file> --tool <name>
   --version <v> --expected <publisher-sha256>` (fails closed on mismatch) after the
   **legal/license review** for the exact distributed versions.
3. Drive each drill above against the live stack, capturing evidence, and record the
   alert thresholds + on-call runbook entries the gate requires.

This gate permits a **human-supervised** production launch only — never unattended
exploitation or automatic submission.
