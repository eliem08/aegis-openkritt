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

The gateway is dual-homed on `model_internal` and `model_egress`. The control
plane joins only `model_internal`; workers join neither model egress nor the
provider secret. No gateway port is published on the host.

## Cost and resilience

The configured V4 Flash price table tracks cache-hit input, cache-miss input, and
output tokens with Decimal arithmetic. Reservations assume cache misses and the
2x peak multiplier. Defaults are USD 2 per hunting cycle and USD 10 per UTC day.
Missing trustworthy usage is intended to charge the reservation maximum once the
durable Redis/PostgreSQL backend is enabled.

The gateway currently implements:

- exact tenant-partitioned caching;
- strict request and response schemas;
- bounded retries with `Retry-After` support;
- a circuit breaker;
- sanitized provider errors;
- thinking-mode controls;
- atomic in-process cost reservations;
- deterministic planner fallback.

## Current production limitations

The live single-container gateway boundary has been validated, but the overall
system is not yet approved for unattended production. Remaining gates include:

- Redis-backed cross-replica cost reservations and PostgreSQL usage history;
- control-plane orchestration wired to the three-pass profitability scheduler;
- real approved scanner release pins and expanded static/dependency/secret tools;
- live worker direct-egress denial on the intended host;
- private OAST and isolated Chromium workflows;
- sustained load, backup/restore, and provider-outage drills;
- human review of DeepSeek data retention for every target program.

Armed hunting remains opt-in, authorized-program-only, non-exploitative, and
human-submitted.
