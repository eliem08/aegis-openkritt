# Automatic profit-aware hunting

`python -m aegis.hunt` runs a bounded three-pass loop:

```text
authorized program scope
  -> pass 1: discover automation/AI-permitted bounty repositories
  -> pass 2: rank expected net value and reserve exploration capacity
  -> pass 3: launch scans only for allocated repositories
  -> collect candidates for human review
  -> sync report outcomes into calibration
```

Dry-run remains the default. The hunter never exploits and never submits reports.

## Portfolio calculation

Each repository is scored as:

```text
p_valid × p_accepted × expected_bounty × uniqueness
  - model_cost - scanner_cost - verification_time_cost
```

The cycle summary exposes every component, selection/skip reason, estimated cost,
net expected value, and whether the bounty amount is missing. A bounty-eligible
flag is not converted into a fictional dollar amount. Provide operator-verified
program payout estimates explicitly:

```powershell
$env:AEGIS_HUNT_EXPECTED_BOUNTIES_JSON='{"program-a":"750","program-b":"1500"}'
```

Known positive-value work ranks before unknown payout work. The exploration
fraction preserves a deterministic slice for new programs and weakness classes;
unknown payouts selected through that slice are labeled
`exploration_missing_bounty`.

Useful controls:

- `AEGIS_HUNT_PORTFOLIO_CAPACITY`: maximum repositories selected per cycle; `0`
  means all repositories that survived discovery caps.
- `AEGIS_HUNT_EXPLORATION_FRACTION`: capacity reserved for uncertain work.
- `AEGIS_HUNT_VALID_PROBABILITY` and `AEGIS_HUNT_ACCEPTANCE_PROBABILITY`:
  operator/calibration priors in `[0,1]`.
- `AEGIS_HUNT_MODEL_COST`, `AEGIS_HUNT_SCANNER_COST`, and
  `AEGIS_HUNT_VERIFICATION_TIME_COST`: estimated USD cost per repository.

## Automatic target selection and authorization

With `AEGIS_HUNT_HANDLES` unset, the hunter inspects authorized programs and
keeps only programs open for submissions whose policy permits automated and AI
tooling and whose structured scope contains bounty-eligible source repositories.
`AEGIS_HUNT_INSPECT_LIMIT`, `AEGIS_HUNT_MAX_PROGRAMS`, and
`AEGIS_HUNT_MAX_REPOS` bound discovery.

Forcing a handle does not bypass policy. The repository pipeline re-reads the
program and structured scope before both discovery and launch. Out-of-scope,
non-submittable, non-code, automation-forbidden, and AI-forbidden assets do not
launch.

## Run it

Start with one dry-run cycle:

```powershell
$env:AEGIS_HUNT_CYCLES='1'
.\.venv\Scripts\python.exe -m aegis.hunt
```

Inspect the `portfolio` section in the cycle summary. It lists selected and
skipped repositories, missing payout data, and estimated economics. Then arm a
small portfolio:

```powershell
$env:AEGIS_HUNT_ARM='1'
$env:AEGIS_HUNT_MODEL='<model-id configured in open-kritt>'
$env:AEGIS_HUNT_PORTFOLIO_CAPACITY='2'
$env:AEGIS_HUNT_HANDLES='program-a'
.\.venv\Scripts\python.exe -m aegis.hunt
```

Prerequisites are a running `AEGIS_OPENKRITT_URL`, read-only HackerOne API
credentials, and a model configured in open·kritt. The dedicated Aegis DeepSeek
gateway is a separate production boundary; an open·kritt model identifier is not
automatically routed through it. Do not assume `deepseek-v4-flash` works in
open·kritt until that backend/provider is explicitly configured and tested.

## Console API

`POST /ui/hunt` runs one cycle. It is dry-run unless `arm` is true. Portfolio
fields can be supplied without changing server environment:

```json
{
  "arm": false,
  "handles": ["program-a"],
  "max_programs": 1,
  "max_repos": 3,
  "portfolio_capacity": 1,
  "exploration_fraction": 0.2,
  "expected_bounties": {"program-a": "750"}
}
```

The response explains all three passes. Human review and human submission remain
mandatory even when armed.
