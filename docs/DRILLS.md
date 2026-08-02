# Phase 5 Failure Drills — Runbook and Status

The Phase 5 completion gate requires load, isolation, failover, restore, rotation,
supply-chain, and kill-switch drills. Drills split into two groups: those runnable
against the local single-node stack (run and recorded here), and those that need
real production infrastructure (HA Postgres, Redis, KMS, a load harness) which is
**not** provisioned in this environment. Nothing below is claimed unless it was
actually executed.

## Runnable locally — EXECUTED, results recorded

Run against the compose Postgres on `:5433` via `scratchpad/drill_pg.py`
(real code, real DB). Latest run (2026-08-03):

| Drill | Result | Evidence |
|---|---|---|
| Durability + reconnect across a DB **restart** | **PASS** | scan/task/reservation state survived `docker restart`; a fresh pool reconnected (`task=queued`, `spend=5.0`) |
| Stale-lease reclaim after a **crashed worker** | **PASS** | expired lease on a `running` task reclaimed → requeued |
| **Idempotent** reservation finalize (no double-commit) | **PASS** | repeat finalize left usage unchanged `(5.0, 0)` |

Also covered by the automated suite (in-process, both engines):
- Multi-worker lease/reservation/approval races — `tests/api/test_reservations.py`,
  `test_reservation_approval.py` (20 racing threads; exactly one winner).
- Kill-switch propagation — `tests/scheduler/test_coordinator.py` (queued→cancelled,
  no new claims).
- Tenant isolation across API/queues/artifacts — `tests/api/test_tenancy.py`,
  `test_scans_api.py`, `tests/coord/test_identity.py`.
- Key rotation / revocation / wrong-key fail-closed — `tests/keys/test_keyring.py`.
- Coordination fail-closed on backend loss + lease reconciliation —
  `tests/coord/test_coord_backend.py`.
- Supply-chain severity/image-pin policy — `tests/supply/`.
- Binary pinning + tamper rejection — `tests/tools/test_pin.py`.

## NOT runnable here — require real infrastructure (blocked, not skipped silently)

| Drill | Needs | Why not here |
|---|---|---|
| PostgreSQL **failover** (primary → replica) | Managed/replicated PG cluster with automated failover | Local compose is single-node; a restart is not a failover |
| **PITR / restore-from-backup** verification | Continuous archiving + a backup target | No archiving/backup target provisioned |
| **Redis** outage/recovery | A real Redis + workers using it | Coordination backend is the in-memory fake; fail-closed logic is unit-tested, not the live outage |
| **KMS/HSM/Vault** rotation + revoked-key | A cloud KMS/Vault | The key ring mechanism is tested; live KMS integration is not wired |
| **Load** test at scale | A load harness + the local synthetic lab at scale | No load harness; per the spec, SLOs must come from load evidence, not invented targets |
| Minimal non-root **seccomp images** + image direct-egress/privilege/filesystem | Built container images + a runtime | Images are a deployment artifact; the policy (SBOM/severity/pin) is tested, the images are not built here |
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
