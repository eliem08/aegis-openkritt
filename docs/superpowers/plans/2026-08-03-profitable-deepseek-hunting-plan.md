# Profitable DeepSeek Hunting Implementation Plan

Design: `docs/superpowers/specs/2026-08-03-profitable-deepseek-hunting-design.md`

## Delivery principles

- Preserve dry-run, human-review, human-submit, and no-auto-exploit defaults.
- Make each boundary independently deployable and testable.
- Keep deterministic discovery and planning available when DeepSeek is disabled.
- Fail closed for scope, authorization, provider egress, paid-work reservations,
  scanner provenance, and evidence promotion.
- Do not claim a production pass for infrastructure that was not exercised live.

## Phase 1 — DeepSeek V4 compatibility and live diagnostics

### Task 1.1: Extend model configuration

Files:

- Modify `src/aegis/ai/config.py`.
- Modify `.env.example`.
- Add or modify `tests/ai/test_client.py`.

Work:

- Change the documented default to the stable API model ID
  `deepseek-v4-flash` while accepting an operator override.
- Add environment-backed connect/read/total timeouts, maximum output tokens,
  temperature, thinking-mode selection, and JSON-mode capability flags.
- Validate numeric bounds and reject unsupported URL schemes or embedded
  credentials.
- Keep `DEEPSEEK_API_KEY` optional outside production.

Tests:

- Defaults and every environment override parse correctly.
- Invalid URLs, timeouts, budgets, and token limits fail before a request.
- Missing key still produces deterministic fallback in development.

### Task 1.2: Add sanitized live diagnostic command

Files:

- Add `src/aegis/ai/__main__.py`.
- Add `tests/ai/test_diagnostic.py`.

Work:

- Provide `python -m aegis.ai doctor`.
- Load the local `.env`, send synthetic content only, require valid JSON, and
  print model, latency, request status, and usage without printing credentials or
  response prose.
- Require an explicit `--live` flag before a paid request.

Tests:

- The default command is offline.
- Sanitization prevents API keys and response content from reaching output.
- Mock success, invalid JSON, auth failure, timeout, and rate limiting.

Verification command:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\ai -q
.\.venv\Scripts\python.exe -m aegis.ai doctor
```

## Phase 2 — Production model gateway

### Task 2.1: Define gateway contracts

Files:

- Add `src/aegis/model_gateway/__init__.py`.
- Add `src/aegis/model_gateway/models.py`.
- Add `src/aegis/model_gateway/config.py`.
- Add `tests/model_gateway/test_config.py`.
- Add `tests/model_gateway/test_models.py`.

Work:

- Define versioned request/response schemas for messages, JSON contracts,
  thinking mode, token bounds, reservation identity, usage, cache status, model
  version, and sanitized errors.
- Reject unknown fields, unbounded payloads, unsupported roles, arbitrary provider
  URLs, and caller-supplied authorization headers.
- Bind every request to tenant, engagement, task, and budget identifiers.

### Task 2.2: Implement provider transport and resilience

Files:

- Add `src/aegis/model_gateway/provider.py`.
- Add `src/aegis/model_gateway/service.py`.
- Add `src/aegis/model_gateway/__main__.py`.
- Add `tests/model_gateway/test_provider.py`.
- Add `tests/model_gateway/test_service.py`.

Work:

- Permit HTTPS only and an exact configured DeepSeek origin.
- Disable cross-origin redirects and revalidate every redirect.
- Apply separate connect/read/total deadlines.
- Implement bounded exponential retry with jitter for eligible `429` and `5xx`
  responses, honoring `Retry-After` within the task deadline.
- Add a stateful circuit breaker with half-open probes.
- Strictly validate JSON output and provider usage.
- Return sanitized error codes rather than raw provider bodies.

Tests:

- Success, retry, retry exhaustion, deadline, circuit open/half-open/closed,
  redirect rejection, invalid TLS origin, malformed response, and missing usage.
- API keys never occur in log records, exception strings, or response bodies.

### Task 2.3: Add exact caching

Files:

- Add `src/aegis/model_gateway/cache.py`.
- Add `tests/model_gateway/test_cache.py`.

Work:

- Build content-addressed cache keys from normalized model parameters, prompt
  content hashes, contract version, and model version.
- Exclude credentials and tenant-private plaintext from cache keys and telemetry.
- Partition cache values by tenant and policy.
- Never reuse semantically similar but byte-different security tasks.

Tests:

- Cross-tenant access is impossible.
- Any material prompt, schema, mode, or model change misses the cache.
- Secrets are absent from keys and metrics.

## Phase 3 — Atomic usage and cost controls

### Task 3.1: Create pricing and reservation domain

Files:

- Add `src/aegis/ai/pricing.py`.
- Add `src/aegis/ai/usage.py`.
- Add `tests/ai/test_pricing.py`.
- Add `tests/ai/test_usage.py`.

Work:

- Represent cache-hit input, cache-miss input, output, and configurable peak
  multipliers as versioned operator data.
- Estimate a maximum charge before launch and reconcile against provider usage.
- Charge the reservation maximum when trustworthy usage is absent.
- Use decimal arithmetic and explicit currency units.

Tests:

- Regular and peak calculations, rounding, cache categories, missing usage, and
  price-version changes.

### Task 3.2: Implement durable atomic budgets

Files:

- Add `src/aegis/model_gateway/budget.py`.
- Extend `src/aegis/coord/redis_backend.py`.
- Extend `src/aegis/api/postgres.py` and migrations.
- Add `tests/model_gateway/test_budget.py`.
- Add optional live Redis/PostgreSQL integration tests.

Work:

- Reserve cycle and daily USD capacity atomically in Redis.
- Persist reservation, provider request, reconciliation, and release records in
  PostgreSQL with idempotency keys.
- Reconcile abandoned reservations and deny new paid work on inconsistent state.
- Apply per-tenant, engagement, model, cycle, day, and concurrency caps.

Tests:

- Concurrent requests cannot exceed a cap.
- Duplicate finalize/release operations are idempotent.
- Crashes between reserve/call/finalize reconcile safely.

## Phase 4 — Hardened production wiring

### Task 4.1: Add secret and network boundaries

Files:

- Modify `compose.production.yml`.
- Modify `production.env.example`.
- Modify `src/aegis/production/bootstrap.py`.
- Modify `src/aegis/production/config.py`.
- Add `tests/production/test_model_gateway.py`.

Work:

- Add a non-root, read-only `model-gateway` service.
- Mount the DeepSeek key only into that service.
- Place the gateway on an internal caller network and a dedicated provider-egress
  network; keep the control plane and workers off provider egress.
- Configure the control plane with an internal gateway URL, never the provider
  key.
- Keep local development capable of direct client use.

Tests:

- Compose structure and production configuration enforce secret ownership and
  network membership.
- Production startup rejects a key exposed to control-plane or worker settings.

### Task 4.2: Extend readiness and drills

Files:

- Modify `src/aegis/production/readiness.py`.
- Modify `src/aegis/production/drills.py`.
- Modify `compose.production.ops.yml`.
- Add `tests/production/test_model_gateway_drills.py`.

Work:

- Add gateway health, live synthetic JSON, budget exhaustion, circuit breaker,
  provider outage, and direct-egress-denial gates.
- Report skipped infrastructure as not configured, never passed.

Live verification:

- Prove control-plane and worker containers cannot resolve/connect to the
  provider.
- Prove only the gateway can connect to the exact DeepSeek origin.
- Prove no container except the gateway can read the DeepSeek secret.

## Phase 5 — Guardrailed client and specialized agents

### Task 5.1: Route production planning through the gateway

Files:

- Modify `src/aegis/ai/client.py`.
- Add `src/aegis/ai/gateway_client.py`.
- Modify `src/aegis/api/config.py`.
- Add `tests/ai/test_gateway_client.py`.

Work:

- Retain injectable transports and the direct development client.
- Add an internal gateway client with typed errors and request identities.
- Select the gateway automatically in production and reject direct provider
  configuration there.
- Preserve deterministic fallback for unavailable or denied model work.

### Task 5.2: Define specialized agent contracts

Files:

- Add `src/aegis/ai/agents/__init__.py`.
- Add `src/aegis/ai/agents/contracts.py`.
- Add focused modules under `src/aegis/ai/agents/`.
- Add `tests/ai/agents/`.

Work:

- Implement small typed tasks for authentication, authorization, injection,
  SSRF/parsers, secrets/crypto, supply chain, races/business logic, client/API,
  and smart contracts.
- Give each agent the minimum source slices and graph evidence.
- Return hypotheses and verification recipes only; agents cannot invoke networks
  or tools.
- Deterministically reject unknown actions, locations outside supplied files,
  missing provenance, oversized rationales, and unsafe verification proposals.

Tests:

- Prompt-injection fixtures cannot add actions, broaden scope, leak secrets, or
  bypass consequence policy.
- Every specialization has valid, invalid, empty, malformed, and fallback cases.

## Phase 6 — More authorized sources and scanners

### Task 6.1: Generalize program sources

Files:

- Add `src/aegis/ingest/source.py`.
- Refactor `src/aegis/ingest/hackerone.py` behind the common contract.
- Add import adapters under `src/aegis/ingest/` for supported Bugcrowd and
  Intigriti exports.
- Add source fixtures and tests under `tests/ingest/`.

Work:

- Normalize scope, bounty tables, automation/AI policy, source revision, and
  authorization expiry.
- Preserve HackerOne behavior and read-only network semantics.
- Fail closed on ambiguous or expired source records.

### Task 6.2: Expand the scanner portfolio

Files:

- Add adapters under `src/aegis/adapters/`.
- Extend `src/aegis/adapters/__init__.py`.
- Extend release-lock and license documentation.
- Add golden fixtures under `tests/fixtures/` and contract tests under
  `tests/adapters/`.

Initial selection criteria:

- prioritize static analysis, dependency inventory, secrets/history, and
  language-aware data flow;
- prefer permissive licenses and arm's-length execution for copyleft tools;
- require maintained releases, machine-readable output, bounded execution, and
  evidence useful for independent verification;
- do not enable a tool in production until its exact release and output schema are
  approved and pinned.

Work:

- Add adapters incrementally, one tool per commit.
- Map every record into the existing provenance graph.
- Quarantine schema drift instead of silently accepting changed output.

## Phase 7 — Corroboration and profitability scheduling

### Task 7.1: Add root-cause candidate clustering

Files:

- Extend `src/aegis/report/dedup.py`.
- Extend `src/aegis/graph/normalizer.py`.
- Add `tests/report/test_corroboration.py`.

Work:

- Merge equivalent candidates while retaining all observations.
- Count only independent sources as corroboration.
- Group related endpoints by root cause and record conflicting evidence.

### Task 7.2: Implement expected-net-value ranking

Files:

- Add `src/aegis/scheduler/profit.py`.
- Extend `src/aegis/scheduler/coordinator.py`.
- Extend `src/aegis/learn/calibration.py`.
- Add `tests/scheduler/test_profit.py`.

Work:

- Score `p_valid × p_accepted × expected_bounty × uniqueness` minus model,
  scanner, and verification costs.
- Expose score components and uncertainty to reviewers.
- Reserve exploration capacity for new programs and weakness classes.
- Do not fabricate bounty amounts; represent missing data explicitly.

Tests:

- Monotonic component behavior, missing values, duplicate penalties, cost caps,
  deterministic tie-breaking, and exploration fairness.

### Task 7.3: Build the three-pass scheduler

Files:

- Modify `src/aegis/hunt/orchestrator.py`.
- Modify `src/aegis/integrations/repo_pipeline.py`.
- Add `tests/hunt/test_portfolio.py`.

Work:

1. Run broad inexpensive discovery.
2. Allocate model analysis to high-value surfaces plus exploration.
3. Verify in descending expected net value within request/time budgets.

Dry-run output must explain selections, skips, estimated cost, and expected value
without launching scans.

## Phase 8 — Verification, learning, and operator experience

### Task 8.1: Version verification recipes

Files:

- Add `src/aegis/orchestrator/verification.py`.
- Extend `src/aegis/model/evidence.py`.
- Extend `src/aegis/report/quality.py`.
- Add verification tests.

Work:

- Require declared preconditions, identity, canary, maximum requests, timeout,
  expected observation, and cleanup.
- Enforce consequence and scope policy before execution.
- Block report-ready promotion without reproducible evidence and provenance.

### Task 8.2: Enrich outcome calibration

Files:

- Extend `src/aegis/learn/memory.py`.
- Extend `src/aegis/learn/store.py`.
- Extend `src/aegis/learn/hackerone_sync.py`.
- Add migrations and learning tests.

Work:

- Store accepted, duplicate, informative, not-applicable, and false-positive
  outcomes with source portfolio, cost, verification time, model/ranker versions,
  program, and weakness class.
- Apply minimum sample sizes and recency weighting.
- Feed only redacted relevant examples back to agents.

### Task 8.3: Add profitability observability

Files:

- Extend `src/aegis/observ/telemetry.py`.
- Extend API/UI review summaries.
- Add telemetry and API tests.

Metrics:

- verified findings per dollar;
- expected bounty value per hour;
- false-positive, duplicate, and acceptance rates;
- model usage/cache/latency/error/cost;
- scanner coverage/schema drift;
- verification and reviewer queue time.

## Phase 9 — Documentation and release gate

Files:

- Modify `PRODUCTION.md`.
- Modify `docs/RUNBOOK.md`.
- Modify `docs/HUNTING.md`.
- Modify `docs/threat-model.md` or the canonical threat-model document.
- Modify `docs/REPO_STRENGTHS_IMPLEMENTATION.md`.
- Add model pricing and scanner-source manifests.

Work:

- Document local direct DeepSeek use versus production gateway use.
- Document separate open·kritt/OpenRouter credentials.
- Document model data-egress, retention review, budgets, kill switches, and
  incident response.
- Record every external source/tool license and exact release status.

Final verification:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
docker compose --env-file secrets/production.env -f compose.production.yml config
docker compose --env-file secrets/production.env -f compose.production.yml -f compose.production.ops.yml --profile drills run --rm production-drills
git diff --check
git status --short
```

## Commit boundaries

1. DeepSeek V4 configuration and doctor command.
2. Model-gateway schemas, provider transport, resilience, and cache.
3. Pricing, atomic budgets, and durable usage ledger.
4. Production gateway secret/network wiring and drills.
5. Gateway client and specialized agent contracts.
6. Program-source normalization and individual scanner adapters.
7. Corroboration, profitability scoring, and portfolio scheduling.
8. Verification recipes, learning, and observability.
9. Documentation, live drills, and readiness corrections.

## Completion rule

A phase is complete only when its targeted tests pass and the full suite remains
green. External tools, provider calls, platform imports, and container/network
claims require a live opt-in check; missing infrastructure remains explicitly
not configured. The final gate authorizes only a human-supervised pilot until
load, recovery, provider-outage, browser, OAST, and direct-egress drills pass on
the intended production host.
