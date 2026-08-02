# Phase 2 — Discovery and Observation Adapters

Status: design approved on 2026-08-02

## Objective

Build a provenance-rich, bounded discovery pipeline using the strongest
maintained behaviors from Subfinder, httpx, Katana, gau, and jsluice. Phase 2
does not execute vulnerability payloads.

## Stage graph

```text
passive domains ──┐
historical URLs ──┼─> normalize/deduplicate ─> live HTTP probe ─> crawl
seeded targets  ──┘                                      └────> JS analysis
                                                               |
                                                        asset snapshot/diff
```

Stages stream results when possible. A downstream stage may start from validated
incremental events while the producer is still running, but task completion is
recorded separately from partial progress.

## Subfinder adapter

Replicate provider isolation, concurrency, provenance, quotas, cancellation,
and wildcard filtering.

- Run a pinned, checksum-verified version with structured output.
- Record each source provider on the observation.
- Apply global and per-provider result caps and timeouts.
- Reject names outside the immutable parent-domain scope.
- Resolve and suppress wildcard-only results before scheduling probes.
- Treat provider failures as diagnostics unless the configured minimum provider
  coverage is not met.

Provider credentials are secret references and are available only to this task.

## gau adapter

Replicate the simple passive-provider protocol for historical URLs.

- Use configured Wayback, Common Crawl, OTX, and URLScan providers.
- Record provider and original observation timestamp when available.
- Normalize URLs without discarding method-relevant query parameter names.
- Apply date, status, MIME, extension, and maximum-result filters.
- Do not send requests to discovered target URLs during this stage.

## httpx adapter

Replicate typed liveness and service observations.

- Emit URL, scheme, method, status, IP, CNAME, TLS, CDN, ASN, technology,
  title, content type/length, response time, and stable body/header hashes.
- Use bounded retries with explicit retry reasons and backoff.
- Preserve vhost, websocket, redirect, and probe diagnostics as typed fields.
- Never expose the tool's service mode directly to untrusted callers.
- Avoid the Python package naming collision by naming the adapter
  `HttpProbeAdapter`.

## Katana adapter

Replicate the standard/headless engine split and safe queue discipline.

- Standard crawling is the default; headless crawling requires the browser
  capability and is disabled until Phase 4.
- Enforce scope before enqueue and again at the network gateway.
- Bound depth, pages per host, total pages, forms, body bytes, and duration.
- Deduplicate canonical URLs and near-identical pages.
- Preserve cookie state only inside the task's credential/session boundary.
- Avoid configured logout paths and back off unhealthy hosts.
- Record discovery source and parent URL for every route.

## jsluice adapter

Replicate AST-based JavaScript analysis rather than regex-only extraction.

- Analyze downloaded JavaScript and inline scripts already acquired through the
  scoped pipeline.
- Emit endpoint, parameter, and secret-candidate events with source location and
  surrounding context.
- Disable generic high-false-positive secret matchers by default.
- Support approved custom matchers with identifiers and severity.
- Never classify a secret candidate as a verified finding without the evidence
  pipeline and sensitive-data policy.

## Normalization and asset graph

Natural keys distinguish domains, services, URLs, routes, parameters, and
technologies. Observations are immutable and retain all sources. Deduplication
updates the derived asset view but never deletes provenance.

Each scan produces an `AssetSnapshot`. Diffs label added, changed, unchanged,
and missing assets. Missing is not treated as removed until a configurable
number of complete discovery scans agree.

## Error handling

Provider errors, target unreachability, parser incompatibility, quota exhaustion,
and gateway blocks have distinct codes. Partial provider success is visible and
never reported as complete coverage. Adapter output-schema mismatch blocks that
adapter version and quarantines its output.

## Tests

- Golden fixtures for each adapter's pinned output version.
- Provenance survives normalization and multi-source deduplication.
- Wildcard domains and out-of-scope assets are rejected.
- Historical discovery performs no target traffic.
- Probe retries and hashes are deterministic under fake transports.
- Crawl queues respect depth/page limits, redirects, logout rules, and scope.
- JavaScript AST fixtures distinguish endpoints, real secret patterns, and
  common false positives.
- Snapshot diff semantics handle incomplete scans without false removals.
- End-to-end fake-binary tests populate a durable asset snapshot.

## Completion gate

Phase 2 is complete when a signed, authorized target produces a durable,
provenance-rich discovery snapshot through all five adapters; every network
request is gateway-audited; partial coverage is accurately represented; and no
active vulnerability payload is sent.

