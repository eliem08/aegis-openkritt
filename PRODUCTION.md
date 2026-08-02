# Production readiness

An honest assessment of what is production-grade today and what is not. The
guiding principle from the operating prompt applies here too: **fail closed, and
don't overclaim.**

## TL;DR

The **deterministic safety core is production-quality**: the policy engine,
authorization/signature verification (HMAC or Ed25519), scope enforcement,
consequence tiers, budgets, kill switch, and the control-plane API are
well-tested (330+ tests), fail closed, and auditable. Control state is **durable**
(SQLite or pooled Postgres, encrypted at rest). What is **not yet
production-ready**: scan/asset/observation state is not yet persisted, external
CLI tools have no enforced network sandbox, principals are not tenant-bound,
authorize/commit is not yet atomic, and the discovery/active-testing tool
integrations are unbuilt (see the phase specs in `docs/`). Run it in **staging /
supervised engagements**, not unattended against production targets.

## Ready for production

- **Policy gate** (`aegis.policy`) — signed authorization objects, wildcard-aware
  scope, consequence tiers, approvals, rate/spend budgets, kill switch. Fail
  closed on every error path; 100+ tests.
- **Control-plane API** (`aegis.api`) — bearer auth with roles, constant-time
  token checks, signature-verified registration, correlation IDs, structured
  JSON logs, `/healthz` + `/readyz`. Defaults fail closed (auth on, signatures
  required).
- **Orchestrator** (`aegis.orchestrator`) — every action gated before it runs;
  two-phase gate/commit so denied work costs no budget; kill switch and
  stop-on-sensitive-data honored; runs in-process or over the API.
- **Ingestion** (`aegis.ingest`) — read-only HackerOne client with retry/backoff
  and Retry-After handling; program rules parsed into scope + automation/AI/rate
  constraints; forbidden-automation programs yield zero permitted actions.
- **Knowledge** (`aegis.knowledge`) — corpus + historical priors feeding
  prioritisation and planning.
- **Outbound scope proxy** (`aegis.netgate`) — every request, redirect hop, and
  resolved IP checked against scope; SSRF/internal ranges blocked; fails closed.
  (Caveat: not fully DNS-rebinding-proof — needs connection-level IP pinning.)
- **LLM planner** (`aegis.ai`) — DeepSeek as a *guardrailed* planner: output
  filtered to allowed actions + in-scope targets, key from env, deterministic
  fallback. The model is never trusted; the gate re-checks.
- **Ed25519 signing** (`aegis.policy.signing`) — asymmetric authorization
  signatures: the control plane signs with a private key, this process verifies
  with a public key it cannot use to forge. Preferred automatically when
  `AEGIS_ED25519_PUBLIC_KEYS` is set (HMAC remains as a fallback).
- **Durable persistence** — SQLite (`AEGIS_DB_PATH`) *or* pooled Postgres
  (`AEGIS_DB_URL`) behind one `Repository` protocol. Engagements, approval
  grants, the append-only audit trail, **kill-switch state**, and spend budget
  survive a restart (a fired kill switch stays fired — fail-safe). The Postgres
  path is validated by integration tests against a real DB (docker-compose).
- **Encryption at rest** (`aegis.api.crypto`) — the audit trail and the
  authorization JSON are Fernet-encrypted when `AEGIS_ENCRYPTION_KEY` is set;
  ciphertext on disk, plaintext only in memory.
- **Packaging** — typed (`py.typed`), pinned build backend, `.env` loader that
  never overrides the real environment, secrets kept out of logs, CI on 3.11/3.12,
  Docker image running as non-root with a healthcheck.

## Not yet production-ready (known gaps)

| Gap | Impact | Path |
|---|---|---|
| **HA topology** | SQLite + Postgres (pooled) are durable; audit + authorization are encrypted at rest (Fernet); no read-replicas/failover config or HSM-backed keys yet | Run Postgres with replication + backups; hold the Fernet/Ed25519 keys in a KMS/HSM with rotation |
| **Rate budget not persisted** | Rate/concurrency reset on restart (conservative: no in-flight load after a restart) | Externalise rate state (Redis) when scaling to multiple workers |
| **Stand-in workers/planner/patcher** | No real testing/fix capability yet | Build real `passive_recon`, `api_agent`, …, and the patch protocol |
| **Single-process** | No horizontal scale; budgets/kill switch are per-process | Externalise budget/kill-switch state (Redis) behind the same interfaces |
| **Key management** | Ed25519 signing is available; rotation/HSM storage of the private key is not built | Store the private key in an HSM/KMS; implement key rotation with overlapping `key_id`s |
| **Secrets in `.env`/env** | Fine for dev; not for prod | Use a secrets manager (Vault, cloud KMS); never bake into images |
| **No PII detector wired** | `stop_on_real_pii` is a flag workers must honor | Add a real sensitive-data classifier at the evidence boundary |
| **Observability is basic** | JSON logs + correlation IDs only | Wire real OpenTelemetry traces/metrics + alerting |

## Deployment (control plane)

```bash
docker build -t aegis-control-plane .
docker run -p 8000:8000 --env-file .env aegis-control-plane   # docs at :8000/docs
```

Behind a TLS-terminating proxy. The network/proxy layer is the **authoritative**
scope enforcement — the in-process `ScopeGuard` is a mirror (defense in depth),
per the operating prompt. Put the egress allowlist there too.

## Configuration & secrets

Set via environment (or `.env` for local only — see `.env.example`):
`AEGIS_API_KEYS`, `AEGIS_SIGNING_KEYS`, `AEGIS_REQUIRE_SIGNATURE`,
`AEGIS_AUTH_DISABLED` (dev only), `AEGIS_HOST`/`AEGIS_PORT`, and
`HACKERONE_API_*` for ingestion. Generate strong secrets:
`python -c "import secrets; print(secrets.token_urlsafe(48))"`.

## Pre-flight checklist

- [ ] Real signing keys set; `AEGIS_REQUIRE_SIGNATURE=1`; `AEGIS_AUTH_DISABLED` unset
- [ ] Operator/agent tokens are strong and rotated; least privilege per caller
- [ ] Network egress allowlist configured at the proxy (authoritative scope)
- [ ] Durable store + encrypted evidence retention wired (replaces in-memory)
- [ ] Kill-switch channel reachable; escalation contacts monitored
- [ ] Program rules re-verified by a human before any active testing
- [ ] TLS in front of the control plane; secrets from a manager, not images
