# aegis — Autonomous Exposure-to-Fix Agent

A **human-supervised bug-bounty research copilot**: it ingests authorized
programs, plans (LLM, guardrailed) and runs scope-enforced detectors, and turns
verified findings into acceptance-grade reports — all underneath a deterministic
policy gate that the prompt calls the *"primary control"* and that decides,
in code, whether any proposed action may run.

> The agent is a planner; this layer is the law. The LLM can never talk its way
> past a gate — every action is classified and checked by code, not prose.

Status: safety core, control-plane API, orchestrator loop (local **or over the
API**), HackerOne ingestion, knowledge base, **outbound scope proxy**,
**guardrailed DeepSeek planner**, an **extensible vulnerability-detector
framework** (BOLA/IDOR, exposed files, open redirect), and **acceptance-grade
reporting** (redact → dedup → quality gates → HackerOne-ready report) —
implemented and tested (**331 tests**). Full worker fleet and the patch protocol
are still partial. See [Roadmap](#roadmap) and [PRODUCTION.md](PRODUCTION.md) for
an honest readiness assessment.

---

## What it enforces

| Guard | Master-prompt § | Module |
|---|---|---|
| Signed, unexpired **authorization object** | §4 | `authorization.py`, `signing.py` |
| **Consequence tiers** (passive → prohibited) & approval policy | §5 | `consequence.py` |
| **Scope** allowlist (mirror of the network layer) | §2 | `scope.py` |
| **Rate / concurrency / spend** budgets | §4, §8 | `budget.py` |
| **Kill switch** (fail closed on stop / health / spike) | §8, §13 | `killswitch.py` |
| Single composing **engine** → one auditable decision | §3, §10 | `engine.py` |

### Design invariants

- **Fail closed.** Any error, ambiguity, or missing input resolves to a
  *blocking* verdict — never to `ALLOW`.
- **Most-catastrophic-first.** Kill switch and authorization validity are
  checked before anything else and short-circuit.
- **Non-mutating decisions.** `authorize()` never spends budget; only `commit()`
  (called after an action actually runs) does. Denied/queued actions cost
  nothing.
- **A planner can only raise a tier, never lower it.** Unknown actions default
  to `SENSITIVE` (human approval).
- **Defense in depth.** Scope here mirrors the network/proxy allowlist; a
  disagreement is a `SCOPE_ESCAPE` incident, not a silent pass.

---

## The decision

`PolicyEngine.authorize(request)` returns a `PolicyDecision` with one of four
verdicts:

| Verdict | Meaning |
|---|---|
| `ALLOW` | Proceed. |
| `REQUIRE_APPROVAL` | Safe once the named approval token(s) are granted — queued, not rejected. |
| `ESCALATE` | Stop and ask a human (missing/expired/ambiguous authorization). |
| `DENY` | Hard stop — prohibited or out of scope; never runs under any framing. |

Every decision is a JSON-serialisable audit record (`decision.as_dict()`)
carrying the tier, all contributing reasons, required approvals, and any
incidents to raise (`SCOPE_ESCAPE`, `PROHIBITED_ACTION_BLOCKED`, `KILL_SWITCH`,
`AUTHORIZATION_TAMPERED`).

---

## Quick start

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate     |  POSIX:  source .venv/bin/activate
pip install -e ".[dev]"
pytest                 # policy-core tests
python examples/demo.py
```

### Configuration (`.env`)

Local secrets and config live in a git-ignored `.env` (copy the committed
template and fill it in):

```bash
cp .env.example .env    # then edit .env
```

It holds your HackerOne API credentials and the control-plane keys. A tiny
stdlib loader (`aegis.env.load_dotenv`) reads it in the entrypoints
(`python -m aegis.api`, the HackerOne example) — the **real environment always
wins**, so CI/production secrets are never overridden. `.env` is ignored by git;
`.env.example` is the tracked reference.

### Minimal usage

```python
from aegis.policy import ActionRequest, Authorization, HmacSignatureVerifier, PolicyEngine

verifier = HmacSignatureVerifier({"kid": "control-plane-secret"})
auth = Authorization(**auth_dict)                       # parsed & validated
auth.signature = verifier.sign(auth.signing_payload(), "kid")
auth.signing_key_id = "kid"

engine = PolicyEngine(authorization=auth, verifier=verifier)

decision = engine.authorize(ActionRequest("api.example.test", "passive_discovery"))
if decision.allowed:
    ...          # run the action via a typed worker tool
    engine.commit(decision)                             # now debit the budget
```

See [`examples/demo.py`](examples/demo.py) for a full walkthrough (allow, scope
escape, prohibited action, approval flow, kill switch) and
[`examples/authorization.sample.json`](examples/authorization.sample.json) for
the authorization-object shape.

---

## Control-plane API

The authenticated FastAPI front door to the policy core. It transports requests
to the gate — every decision is still made by `aegis.policy`, not by the API.

```bash
pip install -e ".[api]"
AEGIS_SIGNING_KEYS='{"kid-1":"control-plane-secret"}' \
AEGIS_API_KEYS='{"op-token":"operator","agent-token":"agent"}' \
python -m aegis.api            # serves on 127.0.0.1:8000 ; docs at /docs
```

**Roles.** `agent` may request decisions and read status; `operator` may also
register/close engagements, grant approvals, and control the kill switch.
Callers authenticate with `Authorization: Bearer <token>`.

| Method & path | Role | Purpose |
|---|---|---|
| `GET /healthz`, `GET /readyz` | — | Liveness / readiness |
| `POST /engagements` | operator | Register a signed authorization → open an engagement |
| `GET /engagements`, `GET /engagements/{id}` | agent | List / inspect |
| `DELETE /engagements/{id}` | operator | Close (soft) |
| `POST /engagements/{id}/decisions` | agent | Evaluate an action (non-mutating) |
| `POST /engagements/{id}/decisions/{rid}/commit` | agent | Debit budget after the action ran |
| `POST /engagements/{id}/approvals` | operator | Grant approval tokens (auto-computed if omitted) |
| `GET/DELETE /engagements/{id}/approvals[/{gid}]` | operator | List / revoke |
| `GET/POST /engagements/{id}/kill`, `POST …/kill/reset` | agent read / operator write | Kill-switch status & control |
| `GET /engagements/{id}/audit` | operator | Recent decision records |

**Two-phase decisions.** `POST /decisions` never spends budget; call
`…/commit` only after the action actually ran. Every response carries a verdict
(`allow` / `require_approval` / `escalate` / `deny`), the tier, all reasons, any
required approval tokens, and incidents (`SCOPE_ESCAPE`, `KILL_SWITCH`, …). Each
request/response is correlated by an `X-Request-ID` header.

Example — request a decision as the agent:

```bash
curl -s localhost:8000/engagements/auth-2026-001/decisions \
  -H "Authorization: Bearer agent-token" -H "Content-Type: application/json" \
  -d '{"target":"api.example.test","action":"passive_discovery"}'
```

**Config (env):** `AEGIS_SIGNING_KEYS` (JSON `{kid: secret}`), `AEGIS_API_KEYS`
(JSON `{token: "operator"|"agent"}`), `AEGIS_REQUIRE_SIGNATURE` (default `1`),
`AEGIS_AUTH_DISABLED` (`1` = dev only), `AEGIS_HOST`/`AEGIS_PORT`. Defaults fail
closed: signatures required, auth on.

---

## Orchestrator loop

The state machine that drives an engagement (§3):

```
INGEST -> PLAN -> GATE/TEST -> TRIAGE -> LEARN
```

The one non-negotiable rule: **every planned action is gated by the policy
engine before a worker runs it**, and budget is only committed after an allowed
action executes (the same two-phase gate/commit the API exposes). By outcome:

| Gate verdict | What the loop does |
|---|---|
| `ALLOW` | run the worker, commit budget, collect candidates + evidence, merge surface |
| `REQUIRE_APPROVAL` | escalate (human-in-the-loop); do **not** run |
| `ESCALATE` | escalate for human review; do not run |
| `DENY` | record as blocked (with the policy reasons/incidents) |

Additional invariants wired in: the **kill switch** halts the whole run; a
worker reporting **sensitive data** (§5) stops that path, records a safety
event, redacts, and escalates — its raw candidates are never stored.

**Triage (§7–§8).** Candidates carrying reproducible evidence (a canary + an
interaction trace) are promoted to canonical `Finding` records, deduplicated by
fingerprint, and prioritised by the risk function
`P(exploit) × business_impact × asset_criticality × exposure × confidence`, then
mapped to an SSVC decision (Act / Attend / Track). Candidates **without**
reproducible proof are returned separately as *hypotheses* — never reported as
findings.

The planner is where an LLM would sit (planner/synthesiser, never source of
truth); the shipped `StaticPlanner` / `ReconThenProbePlanner` are deterministic
so the loop is fully testable. Workers are a typed contract (`Worker`) with
deterministic stand-ins (`PassiveReconWorker`, `ScriptedWorker`) until real
tooling lands.

### The gate: in-process or over the API

The loop never calls the engine directly — it calls a `PolicyGate`. Two
implementations, same loop:

| Gate | Decisions go to | Use |
|---|---|---|
| `LocalGate(engine)` | the in-process `PolicyEngine` | single-process, tests |
| `RemoteGate(base_url=…, token=…)` | the control-plane API over HTTP | agent worker fleet + a central, audited control plane |

With `RemoteGate`, workers still execute on the agent side; only the *gate* is
remote (`POST /decisions`, `…/commit`, approvals via the ledger). The kill
switch is detected from the decision itself (a `KILL_SWITCH` incident), so both
gates behave identically. `RemoteGate` accepts any `httpx.Client`, including
FastAPI's `TestClient`.

```bash
python examples/orchestrator_demo.py      # in-process (LocalGate)
python examples/orchestrator_over_api.py  # over HTTP against a live control plane (RemoteGate)
```

---

## Ingesting programs (HackerOne)

The real **INGEST** source (§4). `aegis.ingest` discovers authorized bug-bounty
programs, parses their rules of engagement, and turns scope into policy inputs.
Discovery is **read-only OSINT** — it never tests anything.

```bash
# offline (bundled sample):
python examples/hackerone_ingest.py
# live — your token is read from the environment, never passed to the tool:
HACKERONE_API_USERNAME=you HACKERONE_API_TOKEN=… python examples/hackerone_ingest.py acme
```

The `HackerOneClient` (Hacker API, HTTP Basic, GET-only) yields a
platform-agnostic `ProgramRules`:

- **Scope** → `scope_guard_entries()` (web assets eligible for submission,
  wildcards preserved), plus out-of-scope hosts and non-web assets.
- **Rules of engagement** → heuristic parse of the policy text for
  *no-automation*, *no-AI*, and *rate-cap* clauses. Parsing can only **raise**
  caution, never silently grant permission; every result is annotated as
  heuristic.
- **`to_authorization_draft()`** → an **unsigned** authorization skeleton for
  the control plane to sign. Crucially, if a program **forbids automated
  tooling, the draft permits no active actions** and records the conflict — the
  agent won't test it. A signed authorization + human confirmation are still
  required before any active testing.

> Boundaries by design: the tool never handles your API token (env only), only
> issues GETs (with retry/backoff + Retry-After), and treats a program's
> published scope as an *input* to the signed authorization — not a substitute.

---

## Outbound scope enforcement (`aegis.netgate`)

The network-layer control the operating prompt insists on (§2): *scope is
enforced by the network, not the agent.* `build_gated_client(scope)` returns an
`httpx.Client` whose **every** request is checked at the transport — so it also
catches requests a worker makes internally (§17) and **each redirect hop**:

- host not in the signed scope → `ScopeViolation` (blocked)
- a redirect that leaves scope → blocked on the next hop
- a host that resolves to a **private/internal IP** → blocked (SSRF guard)
- DNS failure → **fail closed** (blocked)

This is defense-in-depth beside the policy gate; every real worker will make its
requests through it. (Not fully DNS-rebinding-proof — that needs connection-level
IP pinning; documented in the module.)

## The brain: DeepSeek planner, guardrailed (`aegis.ai`)

The LLM is a **planner/synthesiser, never the source of truth** (§1). DeepSeek
(OpenAI-compatible) proposes a plan; `LLMPlanner` then **filters it** so only
actions that are in the permitted vocabulary *and* on in-scope targets survive —
everything else is dropped and recorded. So a hallucinating or prompt-injected
model **cannot** emit a prohibited or out-of-scope action, and the policy gate
re-checks anyway. If DeepSeek is unavailable (no key, API error, bad JSON),
planning falls back to the deterministic planner — the system never depends on
the model.

```bash
DEEPSEEK_API_KEY=… python -c "..."   # or leave unset to run deterministically
```

Key from the environment (`DEEPSEEK_API_KEY`), never handled by the tool or
logged. `LLMPlanner` is a drop-in `Planner`, so the orchestrator uses it
unchanged.

---

## Detectors: any bug class is a plug-in (`aegis.detect`)

The "handle many bug classes smartly" layer. Each class is a `Detector` that
runs through the **scope proxy with per-request gating** — it physically cannot
reach out of scope. Shipped detectors:

| Detector | Class | How it proves impact safely |
|---|---|---|
| `BolaDetector` | IDOR/BOLA (CWE-639) | two **owned** test accounts + a canary — proves cross-account read without touching a real user (§18) |
| `BflaDetector` | function-level authz (CWE-285) | low-privilege owned account reaches a privileged function |
| `MissingAuthDetector` | missing auth (CWE-306) | request a protected endpoint with **no credentials**; flag 200 + signature |
| `ExposedFileDetector` | VCS/config/creds (CWE-538/200) | GET known paths, require a content signature (no SPA false positives) |
| `CorsMisconfigDetector` | CORS (CWE-942) | canary `Origin` reflected **with credentials** — headers only |
| `OpenRedirectDetector` | open redirect (CWE-601) | canary host in `Location`, checked **without following** the redirect |
| `ErrorDisclosureDetector` | verbose errors (CWE-209) | benign malformed input; flag framework/DB stack-trace signatures |

A **`ReconWorker`** discovers endpoints (robots/sitemap/JS/OpenAPI spec) through
the scope proxy and builds the attack surface, so the pipeline maps its own
targets. Add a bug class by writing a `Detector` and registering it — nothing
else changes. `DetectorWorker` bridges detectors into the orchestrator loop.

> Honest scope: this is an *extensible framework with high-value detectors*, not
> a claim that every bug class is covered. New classes are cheap to add; breadth
> grows over time.

## Reports that get accepted (`aegis.report`)

A found bug earns nothing without an accepted report. `prepare_submission`
takes a verified finding → **redacts** credentials/PII from the evidence →
checks **internal + public duplicates** → runs **quality gates**
(reproducible, verified, in-scope, material, redacted, non-duplicate) → renders
a **HackerOne-ready** report (CWE remediation + scope-compliance statement).
Only findings that pass every gate are marked submittable — and **submission
stays human-approved** (§10).

```bash
python examples/full_pipeline_demo.py   # detect -> triage -> submission report (offline)
```

---

## Learning from past reports

The **LEARN** stage (§3, §8, §12). `aegis.knowledge` ingests past disclosed
bug-bounty reports into a corpus and turns them into signal that feeds
prioritisation and planning.

```bash
python -m aegis.knowledge examples/reports.sample.jsonl
```

- **Corpus** (`ReportCorpus`) — load disclosed reports from JSONL/JSON (or map
  HackerOne hacktivity JSON via `map_hacktivity`), filter and persist. Tolerant
  of messy exports; CWE/severity normalised on ingest.
- **Insights** (`CorpusInsights`) — weakness frequency, per-asset-type
  breakdown, average bounty, and **historical priors** `P(weakness | asset_type)`
  — the learned analogue of KEV/EPSS enrichment.
- **Enrichment** (`reprioritize_finding`) — gently blends a finding's
  `p_exploit` toward the historical base rate of its CWE, then recomputes
  priority + SSVC. History informs, weight `0.3` by default — it never decides.
- **Knowledge-aware planning** (`KnowledgeAwarePlanner`) — reorders a base plan
  so probes for historically-common weaknesses run first (recon still first),
  annotating each with its history score.

Everything is deterministic and offline; feed a real export of disclosed reports
to learn from your own history.

---

## Layout

```
src/aegis/policy/
  authorization.py   Authorization model (pydantic, extra="forbid") + validator
  signing.py         Deterministic canonicalisation + HMAC verifier (pluggable)
  consequence.py     ConsequenceTier, action->tier classifier, tier policy
  scope.py           Host allowlist matching (exact + wildcard subdomains)
  budget.py          Token-bucket rate limit, concurrency, spend
  killswitch.py      Fail-closed latch
  decisions.py       Verdict / Reason / ActionRequest / PolicyDecision
  engine.py          PolicyEngine — composes every guard into one decision
src/aegis/api/
  app.py             create_app(config) — the FastAPI factory
  config.py          ControlPlaneConfig, roles, env loading
  security.py        Bearer-token auth + role dependencies
  store.py           EngagementStore, ApprovalLedger, AuditBuffer (in-memory)
  schemas.py         Request/response models
  observability.py   Correlation-id middleware + JSON logging
  routers/           engagements, decisions, approvals, control, audit, system
src/aegis/model/
  attack_surface.py  Asset / Route / Parameter / AttackSurface (mergeable)
  plan.py            PlannedAction, TestPlan, EngagementInputs
  evidence.py        Canary, InteractionStep, EvidenceBundle (§7)
  finding.py         Candidate, Finding, priority + SSVC (§8)
src/aegis/orchestrator/
  planner.py         Planner protocol + Static/ReconThenProbe planners
  workers.py         Worker contract + mock/scripted stand-ins
  triage.py          dedup + prioritise -> findings vs hypotheses
  escalation.py      EscalationQueue (human-in-the-loop)
  gate.py            PolicyGate protocol + LocalGate (in-process)
  remote.py          RemoteGate — drives the loop over the API (needs httpx)
  loop.py            Orchestrator — the gated state machine
src/aegis/ingest/
  program.py         ProgramRules, scope assets, policy-clause parsing
  hackerone.py       HackerOne Hacker API client (read-only, retrying) + mapper
src/aegis/knowledge/
  report.py          DisclosedReport, Severity, CWE normalisation
  corpus.py          ReportCorpus (JSONL/JSON load, filter, persist)
  insights.py        weakness frequency, per-asset priors
  enrichment.py      blend findings with historical priors (§8)
  planner.py         KnowledgeAwarePlanner (history-ordered probes)
src/aegis/netgate/
  scope_transport.py scope-enforcing httpx transport (SSRF + redirect safe)
src/aegis/ai/
  config.py          DeepSeek config (key from env)
  client.py          DeepSeek chat client (OpenAI-compatible, httpx)
  planner.py         LLMPlanner — guardrailed, deterministic fallback
src/aegis/detect/
  base.py            Detector framework (gated context, registry)
  access_control.py  BOLA/IDOR (owned accounts + canary)
  auth.py            missing authentication (CWE-306)
  exposure.py        exposed VCS/config/credential files
  cors.py            CORS misconfiguration (CWE-942)
  redirects.py       open redirect (no-follow)
  recon.py           ReconWorker — endpoint/surface discovery
  worker.py          DetectorWorker (bridges to the loop)
src/aegis/report/
  redact.py          strip credentials/PII from evidence
  quality.py         submission quality gates
  dedup.py           internal + public duplicate detection
  report.py          HackerOne-ready report generation
  pipeline.py        prepare_submission (redact->dedup->gates->report)
tests/               284 tests (+ scope proxy, ai guardrails, detectors, reports)
examples/            *.py demos + *.sample.json / reports.sample.jsonl
Dockerfile · PRODUCTION.md · .github/workflows/ci.yml
```

---

## Roadmap

Stages 1–3 are done. What remains of the operating loop (§3):

- [x] **Policy + Auth core** — the deterministic gate.
- [x] **Control-plane API** (FastAPI) — submit authorizations, request
  decisions, grant approvals, fire the kill switch. (`pip install -e ".[api]"`)
- [x] **Orchestrator loop** — INGEST → PLAN → GATE/TEST → TRIAGE → LEARN, every
  action gated on the engine.
- [x] **Evidence & triage** — canonical finding schema, canary proof,
  reproducibility gate, dedup, risk/SSVC scoring.
- [x] **Wire the loop to the API** — `RemoteGate` drives engagements over the
  control plane (`POST /decisions`, `…/commit`, approvals via the ledger).
- [x] **Program ingestion (HackerOne)** — read-only discovery → scope + parsed
  rules of engagement → unsigned authorization draft.
- [x] **Knowledge base / LEARN** — corpus of past reports → historical priors →
  finding enrichment + knowledge-aware planning.
- [x] **Outbound scope proxy** — per-request + redirect + SSRF enforcement at the
  transport (`aegis.netgate`).
- [x] **LLM planner (DeepSeek)** — guardrailed: LLM proposes, deterministic
  filter + gate dispose; falls back to deterministic planning.
- [x] **Detector framework + high-value detectors** — BOLA/IDOR (owned accounts +
  canary), exposed files, open redirect; each gated per request.
- [x] **Acceptance-grade reporting** — redact → dedup → quality gates →
  HackerOne-ready report; submission stays human-approved.
- [ ] **Broaden detectors** — auth/session, SSRF (safe canary), business-logic,
  more injection classes; plus a passive-recon + asset-change-monitoring worker.
- [ ] **Browser worker** — authenticated multi-step workflows / business logic.
- [ ] **Patch protocol** — reproduce → failing test → fix → verify → PR.
- [x] **Durable persistence (SQLite)** — engagements, approvals, append-only
  audit, **kill-switch state**, and spend survive restarts (`AEGIS_DB_PATH`),
  behind a `Repository` protocol. Postgres is a drop-in for HA.
- [x] **Ed25519 signing** — asymmetric authorization signatures; the agent
  verifies with a public key it cannot forge (`AEGIS_ED25519_PUBLIC_KEYS`).
- [x] **Recon → BOLA auto-wiring** — discovered `/users/{id}` endpoints +
  operator-seeded objects become BOLA targets automatically.
- [x] **Postgres repository** — the same `Repository` over Postgres
  (`AEGIS_DB_URL`), for HA; validated by integration tests against a real DB via
  `docker-compose.yml`. Connection-pooled (`psycopg_pool`).
- [x] **Encryption at rest** — audit trail + authorization encrypted with Fernet
  when `AEGIS_ENCRYPTION_KEY` is set (§12).
- [x] **Pilot prep** — [PILOT.md](PILOT.md) runbook + `examples/pilot_preflight.py`
  (validates scope/gate plumbing before any real target).
- [ ] **Run a supervised pilot** — the only step that moves "proven revenue"; a
  human decision, not more code.
- [ ] **Ingest → control plane wiring** — register a draft authorization for
  operator signing straight from a discovered program.

---

*Signing note:* two verifiers ship. `HmacSignatureVerifier` is symmetric
(shared secret), stdlib-only — fine for an internal control plane.
**`Ed25519SignatureVerifier` is the production choice** (asymmetric): the
control plane signs with a private key; this process holds only the public key
and cannot forge. The control plane prefers it automatically when
`AEGIS_ED25519_PUBLIC_KEYS` is set. Never commit signing secrets — see
`.gitignore`.
