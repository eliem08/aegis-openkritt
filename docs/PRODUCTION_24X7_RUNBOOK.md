# Aegis 24x7 Supervised Operations Runbook

This runbook operates the `codex/production-24x7` milestone. Human review and
submission remain mandatory. Candidate programs in `reports/programs.json` are
never authorization.

## 1. Prerequisites and health

Configure production secrets through the existing `*_FILE` inputs. In addition,
place the operator Ed25519 private key in a mode-0600 file and set:

```powershell
$env:AEGIS_OPERATOR_SIGNING_KEY_FILE='C:\secure\aegis-operator-ed25519.key'
$env:AEGIS_OPERATOR_SIGNING_KEY_ID='operator-2026-08'
```

Run the fail-closed dependency gate:

```powershell
aegis production health --json reports\production-health.json
```

Do not proceed unless `ready` is `true`. Review every cell, including policy
authority, PostgreSQL, workers/Redis, CT, private OAST, Playwright, Android,
gRPC, scanners, egress, artifact acquisition, and model providers.

## 2. Refresh program policy and scope

Export or retrieve the current program policy through an operator-authorized
provider. The resulting JSON must validate as an `aegis.ingest.source.ProgramSnapshot`
and include current `retrieved_at`, `authorization_expires_at`, source hash,
policy text, in-scope assets, exclusions, automation rules, and rate limits.

Never copy `reports/programs.json` into this input. Store the refreshed snapshot
under an operator-controlled path, for example `operator-input/current-scope.json`.

## 3. Dry run

First omit `--confirm-selection`. Aegis displays the exact program, policy source,
freshness, selected assets, automation constraints, and rate cap and exits without
creating authorization:

```powershell
aegis production operator dry-run --snapshot operator-input\current-scope.json `
  --program PROGRAM_HANDLE --asset api.example.com --operator-id OPERATOR_ID `
  --max-requests 100 --requests-per-second 1 --max-cost-usd 2 `
  --runs-dir reports\operator-runs
```

After comparing the displayed selection with the live program page, repeat with
`--confirm-selection`. This creates the immutable manifest, fresh scope digest,
signed authorization, ranked opportunities, and canonical missions. It executes
nothing.

## 4. Prepare a supervised live canary

Select exactly one current in-scope asset. Add only credential references; never
put credentials in the manifest:

```powershell
aegis production operator live-canary --snapshot operator-input\current-scope.json `
  --program PROGRAM_HANDLE --asset api.example.com --operator-id OPERATOR_ID `
  --identity-ref vault:controlled-owner --identity-ref vault:controlled-peer `
  --max-requests 20 --requests-per-second 0.5 --max-cost-usd 1 `
  --runs-dir reports\operator-runs --confirm-selection
```

The preparation command compiles but does not execute. The supervised executor
must call `execute_live_canary` with the canonical `UniversalMissionRuntime`,
current dependency inventory, authorization verifier, and grant signer. The gate
revalidates the manifest chain, authorization window, scope, selected asset,
method, kill switch, and budgets immediately before execution.

Read-only/offline tasks are the default. A controlled-state-change task is
rejected until a separate signed approval is supplied through the canonical
policy authority.

## 5. Emergency stop and recovery

Fire the engagement kill switch using an operator bearer token:

```powershell
curl.exe -X POST "$env:AEGIS_CONTROL_URL/engagements/ENGAGEMENT_ID/kill" `
  -H "Authorization: Bearer $env:AEGIS_OPERATOR_API_KEY" `
  -H "Content-Type: application/json" `
  -d '{"reason":"operator emergency stop"}'
```

Do not reset it until the incident is reviewed. On restart, call
`resume_operator_run` with a newly refreshed `ProgramSnapshot`. Resume fails if
the chain is altered, authorization expired, policy hash changed, or the selected
asset left scope. Completed tasks cannot reopen and a completed task event blocks
duplicate execution.

## 6. Soak operation

Six-hour proof requires at least 21,600 seconds:

```powershell
python -m aegis.production.soak --mode six-hour --duration-seconds 21600 `
  --report reports\soak-6h.json -- pytest -q tests\production\test_operator_workflow.py
```

Twenty-four-hour mode is separate and requires at least 86,400 seconds:

```powershell
python -m aegis.production.soak --mode 24-hour --duration-seconds 86400 `
  --report reports\soak-24h.json -- pytest -q tests\production\test_operator_workflow.py
```

Use the GitHub `Runtime Soak` workflow for hosted Docker execution. Archive the
report artifact and failure timeline. A short CI soak does not satisfy either
promotion gate.

## 7. CVE measurements

Run and report the two metrics independently:

```powershell
python -m aegis.bench.real_cve --json reports\path-hinted-cve.json
python -m aegis.bench.whole_repo_cve --json reports\whole-repository-cve.json
```

Never average or relabel `path_hinted_ground_truth_recall` and
`whole_repository_discovery_recall`. The latter records detector misses,
discovery/reduction misses, unavailable tools, invalid cases, and regressions
separately.

## 8. Evidence and submission

Verify the run before export with `ImmutableRunStore.verify(run_id)`. Export the
immutable manifest, every hash-chained event, canonical evidence objects, scope
and policy snapshots, signed authorization/grants, executor outcomes, and health
and soak reports. A human must reproduce, review program rules, redact sensitive
data, approve the report, and submit it manually.
