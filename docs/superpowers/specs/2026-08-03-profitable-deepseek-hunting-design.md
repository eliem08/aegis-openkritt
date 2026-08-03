# Profitable DeepSeek hunting design

**Date:** 2026-08-03
**Status:** Approved design; awaiting written-spec review
**Primary model:** `deepseek-v4-flash` (currently DeepSeek-V4-Flash-0731)

## Objective

Increase the number of verified, reportable bug-bounty findings per unit of time
and cost across authorized sources. Aegis will combine deterministic discovery,
pinned security tools, specialized DeepSeek analysis, independent verification,
and outcome learning. It will remain scope-limited, non-destructive, and
human-approved for submission.

Success is measured by verified findings per dollar, expected bounty value per
hour, false-positive rate, duplicate rate, and reviewer time. Raw candidate count
is diagnostic only and is not a success metric.

## Non-goals and boundaries

- No automatic report submission.
- No automated exploitation, persistence, denial of service, credential abuse,
  destructive testing, or access outside an explicit authorization record.
- No LLM response becomes a finding without deterministic scope checks and
  evidence-based verification.
- No unsupported scraping of bounty platforms. New program sources use an
  authenticated supported API or a user-provided export.
- No vendoring of incompatible third-party source or datasets. External tools are
  invoked through pinned, checksum-verified adapters with license records.
- DeepSeek V4 Pro is not an automatic fallback. Its use requires an explicit
  operator configuration and separate budget.

## Chosen approach

A staged hybrid portfolio is preferred over an LLM-only or tool-only system.
Cheap deterministic sources explore broadly. Specialized DeepSeek agents spend
tokens only on promising surfaces and synthesize cross-file or business-logic
hypotheses. Independent verification and profitability scoring decide which
candidate reaches human review.

```text
authorized program sources
    -> scope and policy gate
    -> asset/repository discovery
    -> pinned scanner portfolio + specialized DeepSeek agents
    -> normalized candidate graph
    -> independent evidence verification
    -> profitability queue
    -> human review and submission
    -> outcome learning
```

## Architecture

### 1. Authorized program sources

Define a common `ProgramSource` contract that returns a normalized authorization
record, scope rules, bounty eligibility, policy text/provenance, and source-code
or web assets. HackerOne remains the first live source. Bugcrowd and Intigriti are
implemented only when the operator supplies a supported authenticated API or
export; unavailable sources fail closed and do not block other providers.

Every imported scope record carries its source, retrieval time, source revision
or hash, and an expiry. Expired or ambiguous authorization prevents launch.

### 2. Discovery and scanner portfolio

The existing Subfinder, GAU, HTTPX, Katana, Jsluice, Nuclei, and Dalfox adapters
remain the web discovery foundation. Additional adapters are selected by coverage
and evidence quality, initially:

- static source analysis and custom rules;
- dependency and vulnerability inventory;
- secret and repository-history detection;
- language-aware data-flow and supply-chain analysis;
- DNS, port, service, route, JavaScript, API-schema, and parameter discovery.

Each adapter must declare its license, version, binary digest, supported input,
output schema, consequence tier, network requirements, cost class, timeout, and
evidence type. Scanner output is an unverified candidate, not a verdict.

### 3. Production DeepSeek gateway

Add a dedicated `model-gateway` service between the internal control plane and
DeepSeek. The control plane remains on an internal network and never receives the
provider credential. The gateway receives the API key through a Docker secret and
is the only service allowed provider egress. It permits only the configured HTTPS
DeepSeek origin, verifies TLS, rejects redirects to other origins, and emits no
secret-bearing logs.

The gateway owns:

- OpenAI-compatible chat completion calls;
- `deepseek-v4-flash` model selection through configuration rather than a dated
  version hard-coded in application logic;
- strict JSON response contracts and bounded output sizes;
- connect/read/total timeouts, limited retry with jitter for transient failures,
  `Retry-After` handling, and a circuit breaker;
- concurrency isolation per tenant and engagement;
- token usage, cache-hit, latency, error, model-version, and estimated-cost
  telemetry;
- PostgreSQL usage ledger with Redis atomic reservations;
- content-addressed exact prompt-cache keys and provider context caching that
  exclude secrets; semantically similar security tasks are never treated as
  interchangeable cached results;
- configurable peak-price multipliers and fail-closed budget enforcement.

Provider outage, invalid output, exhausted budget, or an open circuit causes the
planner to use its deterministic fallback. These conditions never relax scope or
evidence requirements.

### 4. Specialized analysis agents

DeepSeek tasks are small, schema-constrained, and attack-surface specific. Initial
specializations cover:

- authentication and session management;
- BOLA/IDOR, BFLA, cross-tenant access, and privilege boundaries;
- injection, SSRF, deserialization, template, path, and parser boundaries;
- secrets, cryptography, signature, replay, and token handling;
- dependency confusion, build pipelines, release integrity, and supply chain;
- race conditions, state machines, workflow and business-logic abuse;
- client-side trust boundaries and JavaScript/API contract mismatches;
- smart-contract access control, accounting, oracle, signature, and reentrancy
  properties.

An agent receives the minimum repository slices, normalized graph evidence, scope,
allowed action vocabulary, policy restrictions, and learned examples required for
its task. It cannot launch a tool or network action directly. It returns typed
hypotheses and proposed verification steps for deterministic policy evaluation.

### 5. Candidate graph and corroboration

All tool and model outputs enter one provenance-rich candidate graph. Natural-key
deduplication merges equivalent candidates while retaining every source,
observation, model request identifier, tool version, and timestamp. Independent
sources increase confidence; repeated output from the same source does not.

Candidates are grouped by root cause and affected asset so one underlying flaw
does not create many inflated report opportunities. Conflicting evidence lowers
confidence and enters the reviewer explanation.

### 6. Verification

Verification is consequence-tiered and transport-scoped. It prefers static proof,
response differential, harmless canaries, contract/property checks, or authorized
OAST callbacks. A verification recipe declares preconditions, identity context,
expected observation, maximum requests, timeout, and cleanup.

A report-ready finding requires reproducible evidence, scope provenance, impact,
redaction, and an auditable verification record. Candidates that cannot be safely
verified remain hypotheses and cannot be promoted by model confidence alone.

## Profitability scheduler

The scheduler maximizes expected net value rather than severity or candidate
count alone:

```text
expected_net_value =
    p_valid
  * p_accepted
  * expected_bounty
  * uniqueness_factor
  - model_cost
  - scanner_cost
  - verification_time_cost
```

Inputs include program bounty tables, historical outcomes, weakness-class priors,
asset criticality, evidence strength, source corroboration, likely duplicate age,
program responsiveness, remaining authorization time, and estimated verification
effort. Exploration capacity is reserved so new programs and weakness classes are
not starved by historical bias.

The default cost policy is configurable rather than embedded in code. Initial
operator defaults are a USD 2 model limit per hunting cycle and USD 10 per UTC
day, calculated using the configured worst-case peak multiplier. Reservations are
atomic and charged from provider-reported usage. Missing usage data is charged at
the request's reserved maximum.

The scheduler executes three passes:

1. broad, inexpensive discovery and static analysis;
2. focused DeepSeek analysis of the highest-value surfaces plus an exploration
   sample;
3. independent verification in descending expected net value.

## Learning loop

Human verdicts and platform outcomes update calibration without model fine-tuning.
Accepted, duplicate, informative, not-applicable, and false-positive outcomes are
stored with program, weakness class, source portfolio, evidence features, cost,
and elapsed time. The learning system updates validity, acceptance, duplicate,
and bounty priors with minimum sample sizes and recency weighting.

Prompt examples are selected from redacted, relevant outcomes. Secrets, live
tokens, private response bodies, and disallowed payloads never enter model memory
or cache keys. Model and ranker versions are recorded so regressions can be
identified and rolled back.

## Failure handling

- `401/403`: disable provider calls, alert, and fall back deterministically.
- `429`: honor `Retry-After`, reduce concurrency, and retry within the cycle
  deadline; do not bypass the gateway.
- `5xx`, timeout, or connection failure: bounded retry, then circuit breaker and
  deterministic fallback.
- malformed or schema-invalid output: reject it, record a sanitized diagnostic,
  and use fallback; do not attempt permissive execution.
- budget exhaustion: stop new model reservations while deterministic stages and
  review remain available.
- source authorization expiry or policy ambiguity: cancel pending work for that
  asset and prevent new launch.
- scanner mismatch, unpinned binary, or invalid signature: fail closed for that
  adapter and continue with independent sources.
- database/Redis inconsistency: deny new paid work until reservations can be
  reconciled.

## Observability and operator controls

Dashboards and API summaries expose:

- candidates, verified findings, and report-ready findings by source;
- verified findings per dollar and expected bounty value per hour;
- false-positive, duplicate, and acceptance rates;
- token input/output/cache usage, estimated/actual cost, latency, and error rate;
- scanner coverage, failure, timeout, and schema-drift rates;
- verification queue age and reviewer time;
- scope rejections, policy denials, kill-switch state, and authorization expiry.

Operators can pause globally, by tenant, engagement, provider, tool, program, or
asset. Armed hunting remains opt-in, capped, and human-supervised.

## Security and privacy

- DeepSeek credentials live only in the model gateway's secret mount.
- Repository content is classified before model egress; engagements can disable
  model egress or restrict it to selected files.
- Prompts and responses are treated as untrusted data and are never interpreted as
  commands.
- Logs contain request IDs, hashes, usage, and sanitized errors—not credentials,
  raw secrets, authorization headers, or full private source content.
- All external network operations remain bound to signed scope, budgets, DNS/IP
  checks, redirect checks, and consequence policy.
- Existing human-review, human-submit, and no-auto-exploit boundaries remain.

## Delivery sequence

1. DeepSeek configuration update and live opt-in smoke command.
2. Production model gateway, secret boundary, usage ledger, and egress isolation.
3. Reliability controls: schemas, retries, circuit breaker, caching, and budgets.
4. Specialized agent contracts and portfolio scheduler.
5. Additional pinned scanner/source adapters selected by coverage and license.
6. Cross-source graph corroboration and profitability ranking.
7. Verification recipes, review explanations, and outcome calibration.
8. Production drills, load tests, operator runbooks, and supervised pilot gate.

Each step ships independently with deterministic fallback and does not enable
armed hunting by default.

## Testing strategy

### Unit and property tests

- schema parsing, prompt construction, redaction, cache keys, and model selection;
- atomic token/dollar reservations under concurrency;
- peak-price and missing-usage accounting;
- ranking monotonicity, exploration allocation, and duplicate penalties;
- scope, redirect, DNS-change, private-IP, and consequence invariants;
- candidate deduplication, corroboration, and provenance preservation.

### Contract and integration tests

- DeepSeek mock responses for success, JSON errors, `401`, `429`, `5xx`, timeout,
  partial usage, and model-version changes;
- adapter golden fixtures and schema-drift failures;
- program-source normalization and expired-authorization rejection;
- PostgreSQL/Redis reservation reconciliation;
- control-plane to model-gateway calls with direct provider egress denied.

### End-to-end tests

- opt-in paid DeepSeek smoke test using only synthetic content;
- seeded vulnerable repositories and authorized web labs across supported weakness
  classes;
- cross-source deduplication and independent evidence promotion;
- dry-run hunting with no external mutations;
- armed lab run proving caps, kill switch, budget exhaustion, and recovery;
- backup/restore with usage and outcome history intact.

### Production acceptance gate

The supervised-pilot gate passes only when:

- every enabled scanner and runtime image is digest-pinned and reviewed;
- the model credential is absent from control-plane and worker containers;
- only the model gateway can reach the configured DeepSeek origin;
- direct worker and control-plane provider egress is denied on the deployment host;
- cost reservations remain within limits under concurrency and failure;
- malformed model output cannot create an executable action or report-ready finding;
- browser, OAST, backup/restore, load, kill-switch, and provider-outage drills pass;
- a synthetic end-to-end run produces reproducible evidence with complete
  provenance and no out-of-scope requests.

Passing this gate authorizes a human-supervised pilot, not unattended operation.

## Documentation changes

Update `.env.example`, `production.env.example`, `PRODUCTION.md`, the operator
runbook, hunting guide, threat model, source/tool manifest, cost policy, and the
production readiness report. Documentation must distinguish the direct local
DeepSeek client from the production model-gateway path and explain that open·kritt
uses separate provider credentials unless explicitly routed through OpenRouter.

