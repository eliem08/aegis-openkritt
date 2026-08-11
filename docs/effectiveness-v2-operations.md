# Effectiveness V2 operator workflow

PostgreSQL is the only authoritative production ledger. Configure
`AEGIS_EFFECTIVENESS_BACKEND=postgresql` and provide `AEGIS_EFFECTIVENESS_DB_URL` through the
production secret environment. `AEGIS_PRODUCTION=1` fails closed if SQLite is selected.

The workflow is append-only:

1. `aegis effectiveness ingest-run --input lineage.json`
2. `aegis effectiveness campaign-create --input campaign.json`
3. `aegis effectiveness campaign-event --input campaign-event.json`
4. `aegis effectiveness record-cost --input cost.json`
5. `aegis effectiveness pending`
6. `aegis effectiveness record-outcome --input outcome.json --confirm`
7. `aegis effectiveness amend-outcome --input correction.json --confirm`
8. `aegis effectiveness shadow-rank --input candidates.json`
9. `aegis effectiveness daily --format json|markdown --output report.json`

Corrections must reference `supersedes_outcome_event_id`; records are versioned rather than
rewritten. Campaigns retain the policy/scope digests and operator budgets but do not authorize
execution. Learned rankings, stop-loss output, and exploration allocations are recommendations
only: the production scheduler, PolicyEngine, and ExecutionGrant chain retain authority.

Unknown bounty, machine cost, or operator labor rate remains unknown. The report exposes machine
economics separately, while full realized profit remains null until all required monetary costs
are known. Human review and submission remain mandatory.
