# Phase 4 — Private OAST, Browser Workflows, and Monitoring

Status: design approved on 2026-08-02

## Objective

Support safely correlated out-of-band tests, authenticated multi-step workflows,
sensitive-data containment, and continuous asset monitoring.

## Private Interactsh integration

Deploy a pinned private Interactsh service. Public default servers are disabled
in production. Each OAST session belongs to one tenant, engagement, scan, and
reservation, with:

- authenticated registration;
- unique correlation and nonce material;
- encrypted interactions and protected polling;
- allowed protocol set;
- creation, last-use, expiration, and deletion timestamps;
- short retention and auditable deregistration.

The worker receives only a generated interaction address and opaque session
reference. Private keys, secret keys, and tokens live in the secrets service.
Interactions are matched to an outstanding authorized probe before they can
create evidence. Unmatched events are quarantined.

DNS and HTTPS are enabled first. SMTP, LDAP, SMB-like, and other protocols stay
disabled until separately threat-modeled and authorized.

## Browser worker

Use a pinned Playwright/Chromium image behind the scoped execution gateway.
Workflows use a declarative Aegis schema rather than arbitrary scripts. Initial
steps support navigation, element assertions, form fill, click, wait-for-
condition, response capture, and synthetic canary checks.

The schema forbids arbitrary JavaScript by default. Every navigation, popup,
download, websocket, service worker, and subresource is scope checked. Downloads
are quarantined. Clipboard, local filesystem, camera, microphone, geolocation,
extensions, and browser debugging ports are disabled.

Credential references are resolved into an ephemeral browser context. Contexts
are never shared across tenants or unrelated identities. Logout paths are
avoided unless the workflow explicitly intends to test logout.

## Session-loss monitoring

Capture authenticated baseline discriminators during preflight. Check them
before dispatch and periodically during long scans. A lost session cancels
pending work for that origin and marks coverage incomplete. It does not silently
continue against a login page or affect unrelated origins.

## Sensitive-data classifier

Classify raw HTTP, browser, tool, and OAST artifacts before normalization. The
classifier combines deterministic patterns, structured-field rules, entropy,
context, and tenant-configured markers. It distinguishes credentials, session
tokens, private keys, financial data, direct identifiers, and unrelated user
content.

Detection immediately:

1. cancels the current path;
2. quarantines the artifact encrypted at rest;
3. stores only a redacted classification event in normal product data;
4. creates an operator escalation;
5. blocks report rendering until reviewed or safely discarded.

ML classification may assist but cannot downgrade a deterministic sensitive
match.

## Continuous monitoring and subscans

Build reNgine-inspired behavior without copying GPL code:

- schedules create full discovery scans from a stored immutable configuration;
- snapshots produce added/changed/missing diffs;
- change events can schedule a narrow dependent subscan;
- subscans retain the parent authorization/scope digest and cannot widen it;
- every stage and notification has a durable activity record;
- repeated incomplete scans cannot declare asset removal.

Notifications use typed destinations and encrypted secret references. Deliveries
are idempotent and record attempts, response class, and final status. Messages
contain sanitized summaries and deep links, not raw evidence or credentials.

## Tests

- OAST registration, encryption, correlation, polling, expiration, and deletion.
- Cross-tenant and unmatched interactions remain quarantined.
- Public OAST endpoints are rejected in production configuration.
- Browser tests block out-of-scope navigation, subresources, popups, downloads,
  websockets, and direct egress.
- Workflow cancellation and session loss drain active work.
- Sensitive fixtures are quarantined and absent from normal DB/API/report output.
- Snapshot diffs schedule only authorized, relevant subscans.
- Notification retries are idempotent and leak no sensitive fields.

## Completion gate

Phase 4 is complete when private OAST and browser workflows verify seeded local
lab findings without cross-session leakage, sensitive artifacts cannot pass the
quarantine boundary, and continuous monitoring produces accurate durable diffs
and bounded authorized subscans.

