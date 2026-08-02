# Repository Strengths — Aegis Implementation Ledger

Last reconciled with Aegis commit: `7a7b252` on 2026-08-02

This file is the authoritative delivery ledger for the audited repository
strengths and the corrections discovered during the Aegis reread. Update a row
to `complete` only when its acceptance tests pass and the implementing commit is
recorded.

Status values: `existing`, `partial`, `not-started`, `in-progress`, `complete`,
`blocked`, `declined`.

## Reference-repository strengths

| Reference | Audited license | Strength adopted | Aegis strategy | Phase | Planned Aegis area | Acceptance evidence | Status | Commit |
|---|---|---|---|---:|---|---|---|---|
| projectdiscovery/subfinder | MIT | Concurrent passive providers, provenance, provider quotas, cancellation, wildcard filtering | Pinned adapter | 2 | `adapters/subfinder`, discovery stages | Multi-provider fixture preserves source; wildcard/out-of-scope results rejected | not-started | — |
| projectdiscovery/httpx | MIT | Typed HTTP/TLS/service observations, retries, hashes, resumable probing | Pinned `HttpProbeAdapter` | 2 | `adapters/http_probe`, observations | Golden JSON fixtures; typed service snapshot; retry and hash tests | not-started | — |
| projectdiscovery/katana | MIT | Standard/headless split, bounded queues, session state, dedup, logout avoidance | Pinned adapter; headless enabled in Phase 4 | 2/4 | `adapters/katana`, browser worker | Queue/scope/logout/session tests; direct-egress denial | not-started | — |
| lc/gau | MIT | Pluggable passive historical-URL providers and streaming filters | Pinned adapter | 2 | `adapters/gau`, discovery stages | Provider/timestamp provenance; zero target traffic | not-started | — |
| BishopFox/jsluice | MIT | AST-based endpoint/secret extraction with context and FP discipline | Pinned adapter over acquired JS | 2 | `adapters/jsluice`, classifier | AST golden fixtures; contextual events; secret candidates quarantined | not-started | — |
| s0md3v/Arjun | AGPL-3.0 | Stable baseline, batched anomaly detection, recursive narrowing, individual confirmation | Clean-room native algorithm; no copied source/wordlists | 3 | `discovery/parameters` | Seeded parameter found efficiently; unstable targets incomplete; license check | not-started | — |
| assetnote/kiterunner | AGPL-3.0 | Method/header/body-aware route schemas, wildcard baselines, target quarantine | Clean-room native schema/enumerator using owned/permissive data | 3 | `discovery/routes` | Wildcard FP suppression; bounded route enumeration; license check | not-started | — |
| projectdiscovery/nuclei | MIT | Versioned signed templates, filters, workflows, protocol work pools | Pinned adapter plus Aegis manifest allowlist | 3 | `adapters/nuclei`, template policy | Unknown/unsigned/prohibited templates rejected; request caps enforced | not-started | — |
| hahwul/dalfox | MIT | Reflection-first XSS, DOM/AST analysis, WAF/session awareness, cancellation, resume, SARIF/JSON | Pinned guarded adapter | 3 | `adapters/dalfox` | Bounded local-lab detection; session-loss/cancel/resume tests | not-started | — |
| projectdiscovery/interactsh | MIT | Correlated encrypted OAST sessions, authentication, polling, resumption | Private pinned service and client adapter | 4 | `oast`, `adapters/interactsh` | Encrypted tenant-scoped correlation, expiry, deletion, public-service rejection | not-started | — |
| yogeshojha/rengine | GPL-3.0 | Durable asset history, stage DAGs, subscans, diffs, task ledger, notifications | Clean-room Aegis architecture; no copied GPL code | 1/4 | scheduler, snapshots, notifications | Durable stage/activity history; accurate diffs; authorized subscans | not-started | — |

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
| Tenant-bind principals and engagement access | Current agent/operator roles are global | 1 | Cross-tenant API/worker access denied | not-started | — |
| Atomic policy/resource reservations | Separate authorize/commit can overbook and double-commit under concurrency | 1 | Concurrent DB tests cannot exceed budgets; finalize is idempotent | not-started | — |
| Persist scans, stages, tasks, leases, assets, observations, artifacts | Current repositories persist control state only | 1 | SQLite/PostgreSQL contract plus restart recovery | not-started | — |
| Versioned DB migrations and foreign-key integrity | Current startup schema is create-if-not-exists without migration history | 1 | Upgrade/downgrade refusal and migration checksum tests | not-started | — |
| External-process scoped execution gateway | In-process `httpx` transport cannot constrain CLI tools | 1 | Direct egress, redirect, private-IP, DNS-change tests | not-started | — |
| Derive report scope from authorization | `prepare_submission` currently trusts a caller boolean | 1 | API cannot override an out-of-scope result | complete | 7a7b252 |
| Gate each detector by `detector.action` | Current worker shares one outer action across all detectors | 1 | Mixed detector registry produces separate policy decisions | complete | 7a7b252 |
| Make recon-to-BOLA an orchestrator transition | Current helper is called manually in a test | 3 | Discovery plus owned seed automatically queues BOLA task | not-started | — |
| Strengthen BFLA differential proof | Missing identity/signature can turn a generic 200 into weak evidence | 1/3 | Missing identity is inapplicable; baseline/differential required | complete | 7a7b252 |
| Fix insecure-config warning for Ed25519 | Warning currently checks HMAC keys but not configured public keys | 1 | Ed25519-only production config emits no false missing-key warning | complete | 7a7b252 |
| Correct roadmap and production claims | Documentation currently overstates automatic wiring and has a stale TL;DR | 1 | Documentation consistency check/manual review | complete | 7a7b252 |
| Add sensitive-data classifier at ingestion boundary | Current worker flag relies on detector behavior and regex redaction is downstream | 4 | Sensitive fixture never reaches normal DB/API/report | not-started | — |
| Replace dev Compose database defaults for production | Default password/host port are suitable only for local development | 5 | Production config validation rejects dev credentials/exposure | not-started | — |
| Resolve FastAPI TestClient dependency deprecation | Current suite emits a Starlette/httpx compatibility warning | 1 | Default test suite has no compatibility deprecation | complete | 7a7b252 |

## Phase completion checklist

- [ ] Phase 1: foundation and safety-correction acceptance gate passes.
- [ ] Phase 2: five discovery adapters produce a durable authorized snapshot.
- [ ] Phase 3: guarded active pipeline finds seeded lab bugs within exact limits.
- [ ] Phase 4: private OAST/browser/monitoring and quarantine gates pass.
- [ ] Phase 5: distributed isolation, load, failover, restore, and rotation drills pass.
- [ ] Production documentation matches only tested and enabled capabilities.
- [ ] Legal/license review completed for the exact distributed versions.
- [ ] Supervised pilot approved by a human for a program permitting automation.

## Update rules

1. Change `not-started` to `in-progress` in the same commit that begins a row.
2. Change a row to `complete` only after its named acceptance evidence passes.
3. Record the implementing commit hash when marking complete.
4. Add newly discovered gaps; do not remove history to make the list look done.
5. If a tool version or license changes, reopen the row until reviewed.
6. A disabled feature may be implemented but is not complete until its enablement
   gate and operational documentation pass.

