# DeepSeek V4 production operation

This repository uses `deepseek-v4-flash` as a guardrailed planner and security
analysis model. The model proposes hypotheses and verification recipes; scope,
consequence policy, evidence promotion, and submission remain deterministic or
human-controlled.

## Local validation

The ignored `.env` contains the operator credential. Check configuration without
network access:

```powershell
.\.venv\Scripts\python.exe -m aegis.ai doctor
```

Make one paid synthetic request and print only model, latency, and usage:

```powershell
.\.venv\Scripts\python.exe -m aegis.ai doctor --live
```

The command never prints response content, reasoning content, request IDs, or the
API key.

## Production secret boundary

Create separate ignored secret files from the existing `.env`:

```powershell
.\.venv\Scripts\python.exe -m aegis.model_gateway.bootstrap --output secrets --env-file .env
```

This creates `secrets/deepseek_api_key` and a distinct
`secrets/model_gateway_token`. The provider key is mounted only into the model
gateway. The control plane receives only the internal caller token.

Validate the combined deployment:

```powershell
docker compose --env-file secrets/production.env `
  -f compose.production.yml -f compose.production.model.yml config --quiet
```

The gateway joins `model_internal`, `model_egress`, and the internal-only
`budget_internal` network. Only the gateway receives the provider key. Redis and
PostgreSQL join `budget_internal` for cost reservations and usage audit records;
they do not join model egress. The control plane receives only the caller token,
and no gateway port is published on the host.

## Cost and resilience

The configured V4 Flash price table tracks cache-hit input, cache-miss input, and
output tokens with Decimal arithmetic. Reservations assume cache misses and the
2x peak multiplier. Defaults are USD 2 per hunting cycle and USD 10 per UTC day.

Production fails startup unless both authenticated Redis and verified-TLS
PostgreSQL URLs are present. Redis atomically enforces shared cycle/day ceilings;
PostgreSQL records the reservation, model, price version, token breakdown,
provider request ID, and actual cost. A ledger outage prevents the paid request.

Validate the live ledgers without exposing credentials. The command uses a
unique namespace and reservation, verifies both stores, and removes only its own
validation data:

```powershell
python -m aegis.model_gateway.validate_ledgers `
  --redis-file /run/secrets/redis_url --database-file /run/secrets/database_url
```

The gateway currently implements:

- exact tenant-partitioned caching;
- strict request and response schemas;
- bounded retries with `Retry-After` support;
- a circuit breaker;
- sanitized provider errors;
- thinking-mode controls;
- atomic Redis cross-replica cost reservations with replay protection;
- durable PostgreSQL usage and reconciliation records;
- deterministic planner fallback.

## Current production limitations

The live gateway boundary and durable ledgers have been validated, but the
overall system is not yet approved for unattended production. Remaining gates
include:

- control-plane orchestration wired to the three-pass profitability scheduler;
- real approved scanner release pins and expanded static/dependency/secret tools;
- live worker direct-egress denial on the intended host;
- private OAST and isolated Chromium workflows;
- sustained load, backup/restore, and provider-outage drills;
- human review of DeepSeek data retention for every target program.

Armed hunting remains opt-in, authorized-program-only, non-exploitative, and
human-submitted.
