# Hardened Compose Production Implementation Plan

Design: `docs/superpowers/specs/2026-08-03-hardened-compose-production-design.md`

## Delivery order

1. Generalize the coordination backend protocol and add a real Redis backend
   using atomic Lua operations, health checks, deployment/tenant namespacing,
   authentication, and fail-closed error translation. Add unit tests with a
   protocol-compatible fake client and optional live-Redis integration tests.
2. Extend control-plane configuration with an explicit production mode, Redis
   URL, deployment namespace, private OAST domain, egress-enforcement flag,
   browser image, and scanner lock path. In production mode, validate before app
   construction and forbid all development fallbacks.
3. Add a hardened production Compose project: internal-only control and worker
   networks, a sole dual-homed egress service, PostgreSQL and Redis health checks,
   Docker secrets, non-root/read-only services, resource bounds, and opt-in lab
   and OAST profiles.
4. Add a scoped HTTP egress service with short-lived HMAC authorization tokens.
   Reuse `ScopedExecutionGateway` for destination, method, DNS, redirect, and
   budget policy. Reject CONNECT/general proxy use and redact audit output.
5. Add worker release-lock validation for scanner and Chromium image pins. Make
   readiness reject missing, mutable, unreviewed, or malformed entries.
6. Add secret bootstrap and production-readiness commands. Secret material is
   written only under the ignored `secrets/` directory and never printed.
7. Add PostgreSQL backup/restore verification and a drill runner that records
   pass/fail/not-configured results for database, Redis, egress, pinning, browser,
   OAST, tenancy, kill switch, and bounded local-lab load.
8. Update `PRODUCTION.md`, `docs/RUNBOOK.md`, `docs/DRILLS.md`, and the repository
   implementation ledger so claims match executable behavior.
9. Run targeted tests after every boundary, then the full test suite, Compose
   config validation, image builds where the runtime is available, secret scans,
   and `git diff --check`.

## Commit boundaries

- Redis backend and strict production configuration.
- Hardened deployment and scoped egress service.
- Pin/readiness tooling and operational drills.
- Documentation and final verification corrections.

## Completion rule

Code-backed gates are completed only when their tests pass. Checks requiring a
user-owned domain, TLS certificate, approved third-party binary, image digest,
or external infrastructure remain visibly `not_configured`; they must never be
converted to synthetic passes. The production verdict remains non-zero while a
required gate is not configured.
