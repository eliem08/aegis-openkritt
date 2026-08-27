-- Additive production migration. The application uses the semantically identical
-- bootstrap DDL in aegis.arsenal.ledger for first-run deployments.
CREATE TABLE IF NOT EXISTS arsenal_coverage_records (
  coverage_record_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  capability_id TEXT NOT NULL,
  mode TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  technique_id TEXT NOT NULL,
  asset_classes TEXT NOT NULL,
  implementation_path TEXT NOT NULL,
  backend TEXT NOT NULL,
  backend_version TEXT NOT NULL,
  backend_health TEXT NOT NULL,
  policy_snapshot_digest TEXT NOT NULL,
  asset TEXT NOT NULL,
  authorization_decision TEXT NOT NULL,
  operator_approval_id TEXT,
  execution_grant_id TEXT,
  run_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  executed BOOLEAN NOT NULL,
  execution_timestamp TEXT,
  evidence_digest TEXT,
  result TEXT NOT NULL,
  finding_ids TEXT NOT NULL,
  error_or_block_reason TEXT NOT NULL,
  execution_error_class TEXT,
  negative_control_status TEXT NOT NULL,
  historical_evidence_invalid BOOLEAN NOT NULL,
  schema_version INTEGER NOT NULL,
  payload_digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_arsenal_coverage_capability
  ON arsenal_coverage_records(capability_id,mode,execution_timestamp);
CREATE INDEX IF NOT EXISTS idx_arsenal_coverage_run
  ON arsenal_coverage_records(run_id,mission_id,task_id);
CREATE OR REPLACE FUNCTION arsenal_coverage_reject_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'immutable coverage'; END; $$ LANGUAGE plpgsql;
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'arsenal_coverage_immutable'
      AND tgrelid = 'arsenal_coverage_records'::regclass
  ) THEN
    CREATE TRIGGER arsenal_coverage_immutable
    BEFORE UPDATE OR DELETE ON arsenal_coverage_records
    FOR EACH ROW EXECUTE FUNCTION arsenal_coverage_reject_mutation();
  END IF;
END $$;
