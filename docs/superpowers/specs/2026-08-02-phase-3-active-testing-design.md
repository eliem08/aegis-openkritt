# Phase 3 — Guarded Active Testing

Status: design approved on 2026-08-02

## Objective

Add high-value active testing while minimizing requests and false positives.
Use clean-room implementations of the useful Arjun/Kiterunner behaviors and
strict adapters for Nuclei and Dalfox. Existing Aegis detectors become first-
class stages with detector-specific policy reservations.

## Capability tiers

`benign_request_mutation` covers non-state-changing malformed or reflected
input. `authenticated_testing` covers owned-account authorization comparisons.
`template_scan` covers an allowlisted Nuclei template set. `xss_reflection`
covers bounded reflected/DOM XSS checks. Blind, stored, state-changing, file,
network, code, and headless capabilities require separate explicit approvals.

No adapter may translate one capability into a broader one at runtime.

## Clean-room parameter discovery

Implement behavior from the published operating approach, not copied source:

1. Capture multiple control responses and determine stable comparison features.
2. Disable unstable features using an independent control probe.
3. Test bounded batches of candidate parameter names with synthetic values.
4. Compare status, redirect, normalized headers, stable text regions, length,
   and controlled reflection signals.
5. Recursively narrow anomalous batches.
6. Verify each surviving parameter individually with a fresh synthetic value.

Support GET, form, JSON, and XML only when the authorization permits the method
and content type. Apply request, candidate, depth, time, and anomaly caps. An
unstable target yields an incomplete diagnostic, not a clean result.

Wordlists must be owned, permissively licensed, or generated from the current
authorized asset corpus. AGPL Arjun wordlists/source are not copied.

## Clean-room API route discovery

Define an Aegis route schema containing method, template path, headers, query,
path/body fields, content types, source, and risk annotations. Populate it from
owned or permissively licensed OpenAPI documents and the engagement's discovered
routes.

Before enumeration, establish wildcard baselines and target health. Bound
connections per host, parallel hosts, redirects, request counts, and errors.
Quarantine a target after repeated instability or rate-limit responses. The
AGPL Kiterunner implementation and datasets are not copied or bundled.

## Nuclei adapter

- Pin executable and template repository commits with checksums.
- Load only an Aegis-maintained template manifest containing approved IDs,
  signer, severity, tags, protocols, maximum requests, and capability tier.
- Reject unsigned, tampered, unknown, newly added, or locally referenced
  templates.
- Disable code, JavaScript, file, network, headless, fuzzing, and OAST protocols
  by default. Enabling any requires manifest review and matching authorization.
- Disable automatic template updates during a scan.
- Parse structured results and preserve template/version provenance.
- Enforce per-protocol concurrency, request budgets, host-error caches, and
  cancellation.

## Dalfox adapter

- Use discovery and reflection analysis before payload execution.
- Bound targets, parameters, payloads per parameter, workers, host concurrency,
  rate, request timeout, and whole-target timeout.
- Default to reflected and DOM analysis. Blind/stored modes are disabled unless
  explicitly authorized with private OAST.
- Detect session loss and stop a host group rather than scanning a login page.
- Preserve per-target state for safe resume and distinguish clean, finding,
  cancelled, truncated, and error outcomes.
- Parse JSON/SARIF output; request/response inclusion remains opt-in and passes
  through evidence quarantine.

## Existing detector integration

The orchestrator derives detector tasks from the asset graph. Recon plus
operator-owned seeds automatically creates BOLA tasks. BFLA tasks require a
declared low/elevated identity pair and privileged-response discriminator.

Each detector reserves and gates its own declared action per request. Missing
auth, exposed-file, CORS, redirect, error-disclosure, BOLA, and BFLA detectors
receive explicit target sets from discovery instead of scanning hard-coded
defaults where route evidence exists.

Candidate creation does not equal verification. Verification requires a second
independent replay or differential evidence appropriate to the detector.

## Safety and error handling

- Use only researcher-owned accounts, objects, and canaries.
- Stop a path on unexpected sensitive data, authentication loss, instability,
  rate limiting, gateway block, or scope ambiguity.
- Do not retry state-changing or blind interactions automatically.
- Treat truncated coverage as incomplete, never clean.
- Store only redacted evidence outside quarantine.

## Tests

- Parameter calibration tolerates controlled dynamic content and rejects
  unstable targets.
- Batch narrowing finds seeded parameters with materially fewer requests than
  one-request-per-name enumeration.
- Route wildcard detection suppresses catch-all false positives.
- License tests assert no copied AGPL/GPL code or bundled restricted dataset.
- Nuclei rejects every non-manifest template and prohibited protocol.
- Dalfox cancellation drains workers and session loss stops pending host tasks.
- Every detector request is associated with its detector action/reservation.
- BOLA/BFLA fixtures prove owned-account differential behavior without real data.
- Findings without replayable evidence remain hypotheses and fail report gates.

## Completion gate

Phase 3 is complete when the active pipeline finds seeded vulnerabilities in a
local authorized lab, stays within exact request/capability budgets, produces no
finding from unstable or truncated scans, and rejects all unapproved templates,
payload modes, identities, and routes.

