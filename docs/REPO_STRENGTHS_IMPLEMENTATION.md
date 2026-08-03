# Repository Strengths — Aegis Implementation Ledger

Last reconciled with Aegis commit: `af3f341` on 2026-08-03

This file is the authoritative delivery ledger for the audited repository
strengths and the corrections discovered during the Aegis reread. Update a row
to `complete` only when its acceptance tests pass and the implementing commit is
recorded.

Status values: `existing`, `partial`, `not-started`, `in-progress`, `complete`,
`blocked`, `declined`.

## Reference-repository strengths

| Reference | Audited license | Strength adopted | Aegis strategy | Phase | Planned Aegis area | Acceptance evidence | Status | Commit |
|---|---|---|---|---:|---|---|---|---|
| projectdiscovery/subfinder | MIT | Concurrent passive providers, provenance, provider quotas, cancellation, wildcard filtering | Pinned adapter | 2 | `adapters/subfinder`, discovery stages | Multi-provider fixture preserves source; wildcard/out-of-scope results rejected | complete (digest unpinned) | 5c8de76 |
| projectdiscovery/httpx | MIT | Typed HTTP/TLS/service observations, retries, hashes, resumable probing | Pinned `HttpProbeAdapter` | 2 | `adapters/http_probe`, observations | Golden JSON fixtures; typed service snapshot; retry and hash tests | complete (digest unpinned) | 5c8de76 |
| projectdiscovery/katana | MIT | Standard/headless split, bounded queues, session state, dedup, logout avoidance | Pinned adapter; headless enabled in Phase 4 | 2/4 | `adapters/katana`, browser worker | Queue/scope/logout/session tests; direct-egress denial | complete (digest unpinned) | 2fd909b |
| lc/gau | MIT | Pluggable passive historical-URL providers and streaming filters | Pinned adapter | 2 | `adapters/gau`, discovery stages | Provider/timestamp provenance; zero target traffic | complete (digest unpinned) | 5c8de76 |
| BishopFox/jsluice | MIT | AST-based endpoint/secret extraction with context and FP discipline | Pinned adapter over acquired JS | 2 | `adapters/jsluice`, classifier | AST golden fixtures; contextual events; secret candidates quarantined | complete (digest unpinned) | 5c8de76 |
| s0md3v/Arjun | AGPL-3.0 | Stable baseline, batched anomaly detection, recursive narrowing, individual confirmation | Clean-room native algorithm; no copied source/wordlists | 3 | `active/parameters` | Seeded parameter found efficiently; unstable targets incomplete; license check | complete | 4dfad03 |
| assetnote/kiterunner | AGPL-3.0 | Method/header/body-aware route schemas, wildcard baselines, target quarantine | Clean-room native schema/enumerator using owned/permissive data | 3 | `active/routes` | Wildcard FP suppression; bounded route enumeration; license check | complete | 4dfad03 |
| projectdiscovery/nuclei | MIT | Versioned signed templates, filters, workflows, protocol work pools | Pinned adapter plus Aegis manifest allowlist | 3 | `adapters/nuclei`, template policy | Unknown/unsigned/prohibited templates rejected; request caps enforced | complete (digest unpinned) | c706c69 |
| hahwul/dalfox | MIT | Reflection-first XSS, DOM/AST analysis, WAF/session awareness, cancellation, resume, SARIF/JSON | Pinned guarded adapter | 3 | `adapters/dalfox` | Bounded local-lab detection; session-loss/cancel/resume tests | complete (digest unpinned) | 30ecd91 |
| projectdiscovery/interactsh | MIT | Correlated encrypted OAST sessions, authentication, polling, resumption | Private pinned service and client adapter | 4 | `oast`, `adapters/interactsh` | Encrypted tenant-scoped correlation, expiry, deletion, public-service rejection | complete (server binary unpinned) | fa132d2 |
| yogeshojha/rengine | GPL-3.0 | Durable asset history, stage DAGs, subscans, diffs, task ledger, notifications | Clean-room Aegis architecture; no copied GPL code | 1/4 | scheduler, snapshots, notifications | Durable stage/activity history; accurate diffs; authorized subscans | complete | 7b6227a |

License identifiers apply to the versions audited on 2026-08-02 and must be
rechecked when pinning a release. Keep upstream notices for distributed MIT
binaries. Obtain distribution-specific legal review before release.

## Existing Aegis strengths to preserve

| Capability | Current location | Status | Required follow-through |
|---|---|---|---|
| Deterministic policy and signed scope | `aegis.policy` | existing | Add atomic reservations and detector-specific actions |
| Ed25519 authorization verification | `aegis.policy.signing` | existing | Add managed key identifiers, rotation, revocation, KMS/HSM path |
| HTTP scope-enforcing transport | `aegis.netgate` | partial | Add connection-level DNS pinning and external-process gateway |
| Kill switch and approvals | policy/control-plane | existing | Bind to tenants; propagate to durable leases/process trees |
| SQLite and pooled PostgreSQL control state | `aegis.api.persistence`, `postgres` | existing | Add migrations and focused scan/lease/asset repositories |
| Fernet protection for authorization/audit | `aegis.api.crypto` | partial | Add key identifiers/rotation and protect other sensitive records/artifacts |
| Recon worker and attack-surface model | `aegis.detect.recon`, `aegis.model` | partial | Replace regex-limited coverage with Phase 2 adapters and provenance |
| BOLA helper and detectors | `aegis.detect` | partial | Automatic stage wiring, stronger BFLA differential proof, per-detector gate |
| Evidence, triage, redaction, reporting | `aegis.report`, `aegis.model` | partial | Derive scope; add quarantine classifier; persist durable evidence metadata |
| Supervised pilot documentation | `PILOT.md` | existing | Update after phase gates; do not claim unattended production readiness |

## Required corrections from the 2026-08-02 code reread

| Change needed | Why | Phase | Acceptance test | Status | Commit |
|---|---|---:|---|---|---|
| Tenant-bind principals and engagement access | Current agent/operator roles are global | 1 | Cross-tenant API/worker access denied | complete | 65dc710 |
| Atomic policy/resource reservations | Separate authorize/commit can overbook and double-commit under concurrency | 1 | Concurrent DB tests cannot exceed budgets; finalize is idempotent | complete | a50c281 |
| Persist scans, stages, tasks, leases, artifacts (assets/observations land with Phase 2 normalization) | Current repositories persist control state only | 1 | SQLite/PostgreSQL contract plus restart recovery | complete | 2c206ae |
| Versioned DB migrations and foreign-key integrity | Current startup schema is create-if-not-exists without migration history | 1 | Upgrade/downgrade refusal and migration checksum tests | complete | 8cfaa3d |
| External-process scoped execution gateway (policy authority + fake backend; prod network-namespace egress enforcement is deployment) | In-process `httpx` transport cannot constrain CLI tools | 1 | Direct egress, redirect, private-IP, DNS-change tests | complete | bf0bf9e |
| Derive report scope from authorization | `prepare_submission` currently trusts a caller boolean | 1 | API cannot override an out-of-scope result | complete | 7a7b252 |
| Gate each detector by `detector.action` | Current worker shares one outer action across all detectors | 1 | Mixed detector registry produces separate policy decisions | complete | 7a7b252 |
| Make recon-to-BOLA an orchestrator transition | Current helper is called manually in a test | 3 | Discovery plus owned seed automatically queues BOLA task | complete | c5dce4b |
| Strengthen BFLA differential proof | Missing identity/signature can turn a generic 200 into weak evidence | 1/3 | Missing identity is inapplicable; baseline/differential required | complete | 7a7b252 |
| Fix insecure-config warning for Ed25519 | Warning currently checks HMAC keys but not configured public keys | 1 | Ed25519-only production config emits no false missing-key warning | complete | 7a7b252 |
| Correct roadmap and production claims | Documentation currently overstates automatic wiring and has a stale TL;DR | 1 | Documentation consistency check/manual review | complete | 7a7b252 |
| Add sensitive-data classifier at ingestion boundary | Current worker flag relies on detector behavior and regex redaction is downstream | 4 | Sensitive fixture never reaches normal DB/API/report | complete | 6ca7699 |
| Replace dev Compose database defaults for production | Default password/host port are suitable only for local development | 5 | Production config validation rejects dev credentials/exposure | complete | 0c3600a |
| Resolve FastAPI TestClient dependency deprecation | Current suite emits a Starlette/httpx compatibility warning | 1 | Default test suite has no compatibility deprecation | complete | 7a7b252 |

## Phase completion checklist

- [x] Phase 1: foundation and safety-correction acceptance gate passes. (`4cb7442`)
  - Safety corrections: all complete (rows above).
  - Completion-gate substrate: durable scan model + versioned migrations (`8cfaa3d`),
    scoped execution gateway (`bf0bf9e`), safe process runner (`f4fa9f8`), adapter
    contract + fake adapter (`d35d0be`), the scan coordinator (`1cb0424`), and the
    tenant-scoped scan **API** (`1fdf02b`). The fake discovery adapter runs the full
    gate flow — create → run-next (reservation → lease → process → event →
    quarantine → normalization → persistence) → read, plus cancel and recover —
    **through the real HTTP API on SQLite and (gated) PostgreSQL**, no direct network.
  - Every Phase-1 "Tests" bullet maps to a passing test: tenant-crossing denial,
    reservation caps + idempotent finalize, **single-use approvals consumed
    atomically with a reservation** (`4cb7442`), the six process-runner cases, the
    seven gateway cases, SQLite/Postgres contract + migrations, crash/restart lease
    reclaim with preserved success, report scope non-override, and detector-specific
    actions.
  - Phase-2 boundary (not part of this gate): full asset/observation **graph**
    normalization — the coordinator does Phase-1 event→artifact classification and
    quarantine; the graph lands with the discovery adapters, as the persistence row
    notes.
- [ ] Phase 2: five discovery adapters produce a durable authorized snapshot.
  - Asset/observation graph + normalizer: **complete** (`7d7cc23`). Immutable
    observations with adapter/provider provenance; assets deduplicated by natural
    key (domain/service/URL/route/parameter/technology) with provenance unioned,
    never deleted; out-of-scope and wildcard emissions rejected before storage;
    per-scan `AssetSnapshot` with added/changed/unchanged/missing diffs where
    missing is never a removal until N *complete* scans agree. Durable on SQLite +
    Postgres via migration 0003, wired into the coordinator.
  - Five discovery adapters: **built and tested** (`5c8de76`) against golden
    fixtures per pinned version, with the per-adapter error/partial-coverage codes.
    All five feed one provenance-rich graph; katana and jsluice corroborate the
    same route and deduplicate to a single asset retaining both sources.
  - Remaining before the box is ticked:
    1. **Release digests are not pinned.** Every adapter declares
       `executable_digest=""` and refuses to run (fail closed). Pinning requires
       downloading the exact releases — and the legal/license review for the
       versions actually distributed, which is still outstanding.
    2. **No adapter has been run against its real binary.** Parsing is proven only
       against recorded fixtures, so a live-output mismatch is possible until a
       pinned run happens.
    3. **Gateway-audited egress for external binaries** remains deployment-level
       (network-namespace) enforcement, as the Phase 1 gateway row already notes.
  - Closed since (`2fd909b`): the katana **cookie/session boundary** (task-scoped,
    host-confined, never in argv or output, wiped on close) and **streaming stage
    handoff** (provisional observations + a separate task_progress record, so a
    consumer can start from validated partial events while completion stays
    distinct; a quarantined stream is never promoted into the graph).
- [x] Phase 3: guarded active pipeline finds seeded lab bugs within exact limits.
  (in-process lab gate; live binary runs still gated on digest-pinning + legal review)
  - Clean-room **parameter discovery**: algorithm complete (`5a23327`) —
    calibrate (stable-feature detection, unstable-target rejection) → batched
    marker probing → recursive bisection → individual verification, with request/
    candidate/depth/time/anomaly caps and capability/method authorization. Found
    seeded params with 8.5x fewer requests than one-per-name; drops survivors that
    do not reproduce alone. No AGPL Arjun source/wordlists used.
  - Clean-room **route discovery**: schema + enumerator complete (`c25e347`) —
    OpenAPI/discovered population with risk annotations, wildcard/catch-all
    baseline suppression, safe-method-only existence probing, and health-based
    quarantine. No AGPL Kiterunner source/datasets used.
  - **Nuclei** adapter: complete (`c706c69`) — signed Aegis template manifest is
    the only source of runnable templates; unknown/newly-added, tampered,
    unsigned, locally-referenced, and prohibited-protocol templates rejected;
    auto-update/OAST/headless/fuzzing disabled; results become FINDING candidates
    (unverified) with template/commit provenance.
  - **Dalfox** adapter: complete (`30ecd91`) — reflected/DOM only by default,
    blind/stored refused without OAST authorization, bounded, session-loss stops
    the host, distinct clean/finding/cancelled/truncated/error/session-loss
    outcomes, per-target resume, JSON+SARIF parsing, FINDING candidates.
  - **Detector orchestration**: complete (`c5dce4b`) — recon→BOLA transition
    (deferred P1 correction) derives detector tasks from the asset graph; owned
    seed on a discovered route auto-queues BOLA; route detectors get explicit
    targets from discovery and are skipped (not defaulted) without route evidence;
    BFLA gated on a real identity pair + discriminator; per-detector reservations;
    and candidate≠verification (differential or second replay).
  - **Stage-wiring + license test**: complete (`4dfad03`) — the parameter/route
    engines run through the real ScopedExecutionGateway (scope/method/DNS/budget
    enforced per probe) emitting PARAMETER/ROUTE events into the graph; automated
    license test asserts no copied AGPL/GPL source or bundled dataset.
  - **Lab completion gate**: passes (`d3b6410`) — an in-process authorized lab
    (seeded BOLA object + canary, hidden/reflected parameter, discoverable routes;
    no binaries, no network) driven end-to-end through the real pipeline: discovery
    populates the graph, the recon→BOLA transition plans a task off it + an owned
    seed, the real BOLA detector confirms the seeded cross-account read and the
    candidate verifies on differential evidence; request accounting is exact
    (engine→gateway→lab) and never over budget; unstable and truncated scans yield
    incomplete-not-clean; and the unapproved is rejected (out-of-scope routes,
    missing BFLA identity, blind XSS without OAST, non-manifest Nuclei templates).
  - **Standing caveat (Phases 2–3):** the pipeline is proven in-process against a
    synthetic lab and recorded golden fixtures. It has **not** run against the real
    pinned binaries (subfinder/gau/httpx/katana/jsluice/nuclei/dalfox) — every such
    adapter fails closed on an unpinned `executable_digest`. Pinning + a live lab
    run remain blocked on the outstanding legal/license review for the exact
    distributed versions.
- [x] Phase 4: private OAST/browser/monitoring and quarantine gates pass. (`7b6227a`)
  (in-process gate; live Chromium/Interactsh server binaries still gated on pinning + legal review)
  - **Sensitive-data classifier + quarantine boundary**: complete (`6ca7699`) —
    deterministic/structured/entropy/context/tenant-marker classification into
    credential/token/key/financial/identifier categories; ML cannot downgrade a
    deterministic match; on a hit the path cancels, the raw artifact is quarantined
    encrypted at rest, only a redacted event reaches product data, an operator
    escalation is raised, and report rendering is blocked. Wired as the normalizer
    ingestion gate + coordinator quarantine (sensitive fixture never reaches the
    graph/observations/summary).
  - **Private OAST**: complete (`fa132d2`) — tenant/engagement/scan/reservation-
    bound authenticated sessions, secrets held in the secrets service (worker sees
    only the interaction domain + opaque ref), interactions encrypted at rest and
    matched to an outstanding authorized probe before becoming evidence, everything
    unmatched/cross-tenant/disabled/foreign quarantined, protected polling, expiry/
    deregistration/retention, and public-server rejection in production. (Pinning
    the actual Interactsh server binary remains a deployment step.)
  - **Continuous monitoring/subscans + notifications**: complete (`07351d1`) —
    immutable-config schedules, diff-driven bounded subscans that cannot widen the
    parent scope digest, removals only from agreeing complete scans, durable
    activity records, and idempotent sanitized notifications with encrypted secret
    refs.
  - **Session-loss monitoring**: complete (`ae9b7ca`) — preflight discriminators,
    periodic re-checks, per-origin drain-on-loss that never touches other origins.
  - **Browser worker**: complete (`8084dd2`) — declarative no-JS schema, every
    navigation/subresource/popup/websocket/service-worker scope-checked, downloads
    quarantined, capabilities disabled, ephemeral per-tenant/identity contexts,
    logout avoidance.
  - **Lab completion gate**: passes (`7b6227a`) — OAST + browser verify seeded
    findings without cross-session leakage, sensitive artifacts cannot cross the
    quarantine boundary, and monitoring produces accurate diffs + bounded subscans.
  - **Standing caveat (Phases 2-4):** proven in-process against synthetic labs +
    golden fixtures; the real pinned binaries (discovery/active tools, the
    Interactsh server, the Chromium image) have not been run live — all fail closed
    on unpinned digests, blocked on the outstanding legal/license review.
- [ ] Phase 5: distributed isolation, load, failover, restore, and rotation drills pass.
  - **Production-readiness validation**: complete (`0c3600a`) — rejects dev/Compose
    DB defaults, weak/untenanted posture, SQLite-as-HA, and public OAST (closes the
    last deferred correction).
  - **Versioned key management**: complete (`ecd6162`) — envelope encryption with
    key ids, overlapping rotation windows, rewrap, fail-closed on missing/revoked.
  - **Distributed coordination**: complete (`8be5a19`) — Redis-shaped rate buckets/
    semaphores/cancellation/dedup with fail-closed admission on backend loss
    (active denied, passive may pause) and lease reconciliation from durable state.
  - **Signed worker identities + typed capability queues**: complete (`ef99e84`) —
    short-lived signed identities, capability-gated queue claims, mutual auth.
  - **Observability facade**: complete (`7d11497`) — OTel-shaped spans/metrics/logs
    with pseudonymous tenants and redaction; canonical metric names.
  - **API/operational protection**: complete (`fa83580`) — per-tenant rate limits/
    quotas, body-size limits, capped pagination, short-lived service identities,
    audited break-glass.
  - **Supply-chain policy**: complete (`3e4baab`) — SBOM + license notices, image
    digest pinning, severity gate with time-limited exceptions.
  - Remaining (genuinely operational — NOT code, cannot be ticked in-process):
    real Redis/PostgreSQL replication-failover-PITR-restore drills; KMS/HSM/Vault
    integration + rotation jobs; building the minimal non-root seccomp adapter
    images and wiring dependency/image scanners; exporting telemetry to a real OTel
    backend and deriving SLOs from load tests; deployment manifests + autoscaling;
    and the live failure drills. The Phase 5 completion gate needs real
    infrastructure + operator runbooks and is not reachable from tests alone.
- [ ] Production documentation matches only tested and enabled capabilities.
- [ ] Legal/license review completed for the exact distributed versions.
- [ ] Supervised pilot approved by a human for a program permitting automation.

## Post-spec detector expansion (ground-truthed against a real report corpus)

Beyond the five phase specs, the detector suite was expanded from a corpus of ~129
real broken-access-control/bug-bounty reports (`[[mdpsec-report-corpus]]`). All are
safe (read-only, static, or out-of-band), emit unverified candidates, and are wired
into detector-planning + `surface_candidates` (reporting). Commits:
- identifier enumeration-risk (`af34733`), auth-posture differential (`8b8a2b2`),
  cross-tenant access control (`ba4c61f`), OAST-backed blind SSRF (`09ca134`),
  first-party JS secrets (`3a4fd5b`), HTTP response-hardening (`51ff6d0`), client-
  side postMessage/origin (`8bd175d`), GraphQL auth-gap (`89716f1`), path-
  normalization bypass (`9d63034`), and the planning/reporting wiring (`af3f341`).
- **Deliberately excluded** (state-changing → held behind the human-approval
  boundary, never auto-exploited): business-logic/price tampering, gift-card/
  entitlement races, mutable-identity-claim ATO.
- lab-only Solidity safety-property analysis (`aegis.active.contract_props`) — a
  static, property-checking pass (no compile/execute/chain) over source the
  operator supplied for an authorized engagement. States the invariants a
  value-holding contract must hold and flags the TVL-drain vectors that violate
  them: reentrancy (external call before the balance settles), missing access
  control on high-authority ops / arbitrary-recipient transfers, unsafe value
  arithmetic, unchecked `.call`, `tx.origin` auth, unguarded `selfdestruct`/
  `delegatecall`. Every hit is a candidate (`verified=False`) for a human + a real
  prover to confirm; it touches no live protocol and asserts no disclosure.
  Wired into detector-planning (`plan_detectors(contracts=...)` → a static, offline
  `contract_review` task) and reporting (`surface_candidates(contracts=...)`).

## open·kritt integration — arm's-length, AGPL-safe (see `docs/OPENKRITT_INTEGRATION.md`)

[open·kritt](https://github.com/Kritt-ai/open-kritt) is **AGPL-3.0**, so its source
is *not* vendored — that would relicense all of Aegis under the AGPL (incl. §13's
network-source clause), the exact clean-room line the reference-tool policy holds.
Instead `aegis.integrations.openkritt` talks to it over its public finding contract:
`ingest_openkritt_findings(...)` maps its `vulnerabilities` export (the eight-key
`json_answer` + dedupe/rank wrapper) into unverified Aegis candidates, respecting
open·kritt's own dedup/severity and mapping `vulnerability_type` → CWE; wired into
reporting via `surface_candidates(openkritt_findings=...)`. Two boundaries kept:
imported rows stay candidates (must pass Aegis's verification gate, not open·kritt's
`exploitable`/rank), and the `malicious_input_example` payload is never surfaced.
A live connector `OpenKrittClient` (arm's-length HTTP, `httpx`, mock-transport
tested) pulls a running backend's `/api/scans/{id}/vulnerabilities` through the same
ingest; `AEGIS_OPENKRITT_URL` configures it.

## Review console UI (`GET /ui`)

The control plane serves a self-contained **review console** — one ranked,
source-labeled, de-duplicated view over candidates from every source (native
analyzers, the contract-property pass, imported open·kritt findings), built by
`aegis.report.build_console`. Data loads live from a connected open·kritt backend
(`GET /ui/review?scan=`) or an uploaded export (`POST /ui/review`). Cross-source
duplicates collapse by fingerprint (an open·kritt reentrancy finding merges with
Aegis's own contract-pass reentrancy). It is a human-review surface: every row
carries its verification status and no exploit payload reaches it.

## Phase 5 operational drills — executed where runnable (see `docs/DRILLS.md`)

Previously-"blocked" drills made real and passing (`0101ee3`): a Redis outage
fails closed and reconciles from durable leases on recovery; 80 concurrent
reservations never overbook a cap of 10; the kill switch drains in-flight work;
and a **live** Postgres backup/restore (`pg_dump -Fc` → wipe → `pg_restore
--clean` → verify) round-trips cleanly. Genuinely infra-bound drills (HA failover,
live KMS rotation, production-scale load/SLO, seccomp image builds, rolling
upgrade) stay honestly marked blocked — not faked.

## Program status (as of `af3f341`, 2026-08-03)

All corrections complete; all 11 reference-tool rows complete. Phases 1-4 pass their
in-process gates; Phase 5's in-process pieces are complete. **949 tests pass on
SQLite; the full gated suite passes on PostgreSQL.** The two things that remain are
NOT code and cannot be ticked here: (a) pinning + live-running the real third-party
binaries (blocked on the outstanding legal/license review — every such adapter fails
closed on an unpinned digest), and (b) standing up production infrastructure for the
Phase 5 operational drills. The platform is code-complete for a **human-supervised**
pilot; it permits neither unattended exploitation nor automatic submission.

## Update rules

1. Change `not-started` to `in-progress` in the same commit that begins a row.
2. Change a row to `complete` only after its named acceptance evidence passes.
3. Record the implementing commit hash when marking complete.
4. Add newly discovered gaps; do not remove history to make the list look done.
5. If a tool version or license changes, reopen the row until reviewed.
6. A disabled feature may be implemented but is not complete until its enablement
   gate and operational documentation pass.

## Hardened single-server production update (2026-08-03)

The earlier program-status paragraph is historical. The following implementation
supersedes its claims about Redis, worker egress, learning persistence, and
single-server recovery:

| Capability | Status | Evidence |
|---|---|---|
| Real Redis coordination with atomic rate/semaphore operations | complete | `c67da61`; fail-closed unit coverage |
| Production-only configuration and file-mounted secret validation | complete | `c67da61` |
| Signed scoped HTTP egress service | code-complete | `c67da61`; live container isolation still requires Docker drill |
| Hardened Compose networks, TLS bootstrap, non-root/read-only app services | statically complete | `c67da61`; Compose config validates |
| Runtime scanner release lock and executable checksum verification | complete | `fbf6520`; real releases remain operator/legal-review supplied |
| PostgreSQL learning outcomes and submission ledger | complete | `fbf6520`; live integration test is DSN-gated |
| Authenticated encrypted backup and archive verification | complete | `fbf6520` |
| Disposable isolated database restore and integrity verification | complete | `fbf6520`; live run requires the production PostgreSQL service |
| Machine-readable production drill verdict | complete | `fbf6520`; required `not_configured` gates fail the verdict |
| Digest-pinned Chromium workflow in an isolated worker | not-configured | requires reviewed image digest and live browser drill |
| Private OAST registration/callback/expiry/teardown | not-configured | requires user-controlled domain, TLS, and deployed endpoint |
| Container image builds and direct-egress denial proof | not-run | Docker engine unavailable during this implementation run |
| HA Postgres/Redis, PITR, KMS/HSM/Vault, rolling upgrades | blocked | distributed infrastructure, outside single-server scope |

The repository remains fail-closed: no placeholder digest, fake browser, public
OAST, missing executable, or skipped infrastructure check can produce a production
pass. See `PRODUCTION.md` and `docs/DRILLS.md` for the executable gate.
