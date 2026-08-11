# Effectiveness Measurement V1 Implementation Plan

## Constraints

- Preserve the 32-technique runtime and production scheduler unchanged.
- PostgreSQL is authoritative in production; SQLite is test/development only.
- Raw lineage, facts, outcomes, corrections, and shadow decisions are append-only.
- Human submission remains mandatory.
- Unknown bounty remains `NULL` and is never coerced into earned revenue.

## 1. Domain and repository contract

Create `src/aegis/effectiveness/` with immutable domain models for lineage subjects,
lifecycle facts, outcome events, confidence states, shadow batches/entries, and
storage health. Add deterministic canonical payload digests and validation for
identifiers, timestamps, decimal money, correction chains, and outcome states.

Define one repository protocol used by both backends. Its write methods return an
idempotent insert result and distinguish an identical retry from an idempotency
conflict. It exposes read methods for lineage resolution, latest outcome versions,
facts, aggregate input rows, and shadow history.

Tests: model validation, nullable bounty, timestamp ordering, digest stability,
correction validation, and interface contract helpers.

## 2. Versioned migrations and storage validation

Add namespaced effectiveness migrations rather than sharing the control-plane
`schema_migrations` namespace. Implement equivalent PostgreSQL and SQLite logical
schemas with subjects, facts, outcome events, shadow batches, and shadow entries.

PostgreSQL DDL uses `NUMERIC`, foreign keys, unique/idempotency constraints,
grouping indexes, and triggers that reject update/delete on raw ledger tables.
Migration execution uses a dedicated PostgreSQL advisory lock.

SQLite mirrors semantics for tests and local development. A storage factory checks
`AEGIS_PRODUCTION`; choosing SQLite in production raises
`EffectivenessStorageStateError` before opening the ledger.

Tests: migrations, indexes/constraints, immutable triggers, production fail-closed,
restart round trip, and schema parity.

## 3. Transactional ingestion service

Add a lineage resolver that validates a canonical immutable run document and its
digest, selects the exact mission/opportunity, and constructs the immutable subject
and lifecycle facts. Insert them in one transaction.

Add outcome recording that requires an existing subject, canonicalizes the payload,
and writes an initial version or explicit correction. The PostgreSQL implementation
uses a transaction, row/advisory locking where needed, and unique constraints so
concurrent identical writes return one event while conflicting retries fail.

Tests: missing lineage, wrong digest, mismatched technique/program/asset, exact
retry, conflicting retry, correction history, rollback, and concurrent PostgreSQL
recording.

## 4. Metrics and confidence

Build deterministic aggregates overall and by technique, weakness family, program,
asset class, authentication mode, and execution mode. Use Decimal for bounty/cost
math and report unknown-bounty counts separately.

Implement funnel counts, externally resolved acceptance/duplicate denominators,
economic totals, realized profit, realized EV, triage duration, profit/hour, and
uncertainty intervals. Apply confidence boundaries at 0, 5, 15, and 30 resolved
outcomes.

Tests: positive/negative controls, zero denominators as `NULL`, rejected exclusion,
nullable bounty, exact cost components, confidence boundaries, and grouping.

## 5. Shadow profitability ranking

Add an offline comparator that accepts canonical opportunities plus their existing
scores/orders. Derive learned estimates only for calibration-eligible groupings;
otherwise preserve existing-prior values with an explicit fallback reason. Persist
the full original and learned order in one immutable shadow batch.

Do not import this comparator into the live mission scheduler or profit-feedback
path. Add a regression test asserting the production scheduler code and decisions
remain unchanged when effectiveness data is present or unavailable.

Tests: insufficient-data fallback, calibration-eligible ranking, deterministic
ties, persistence, backend outage fallback, and no authority mutation.

## 6. CLI and reports

Extend the root CLI with:

- `aegis effectiveness ingest-run`;
- `aegis effectiveness record-outcome`;
- `aegis effectiveness shadow-rank`;
- `aegis effectiveness report --format json|markdown`.

Production commands require the PostgreSQL DSN through existing secret-loading
rules. Human outcome writes display resolved lineage and require confirmation.
Commands return structured storage states and non-zero failures for unavailable
storage, invalid input, cancellation, or conflicts.

Generate deterministic report models/renderers with overall, technique, weakness,
program, asset-class, authentication, and execution-mode sections. Do not add a new
execution UI in V1.

Tests: CLI success, cancellation, invalid lineage, production SQLite rejection,
unavailable PostgreSQL, deterministic JSON/Markdown, and no fabricated data.

## 7. Production health and compatibility

Add an effectiveness dependency result to production health. It is required for
outcome recording and learning commands but does not make otherwise healthy hunting
unavailable. Report `READY`, `DEGRADED`, or `UNAVAILABLE` explicitly.

Keep existing learning APIs compatible. Do not migrate or reinterpret historical
SQLite records as authoritative real outcomes automatically.

Tests: ready PostgreSQL, unavailable PostgreSQL, optional hunting health behavior,
and existing-prior fallback.

## 8. Validation and publication

Run focused tests after every layer, then changed-file Ruff, the full test suite,
PostgreSQL integration/concurrency tests in Docker, and repository CI-equivalent
checks. Confirm the scheduler/technique contract suite remains unchanged. Commit
logical layers, push `codex/hunting-effectiveness`, open/update a draft PR, and
report exact results and unavailable dependencies without changing readiness scores.
