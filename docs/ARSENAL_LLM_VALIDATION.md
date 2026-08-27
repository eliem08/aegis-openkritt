# Arsenal and AI/LLM validation operations

The arsenal subsystem measures three independent facts: capability implementation, current
backend health, and evidence-backed execution. Registration or binary presence never counts as
execution. Historical execution never grants current authority.

## Non-targeting inventory audit

`aegis arsenal audit` accepts no target. It federates canonical registries, performs bounded local
binary/version probes, verifies immutable historical run/evidence chains, and emits deterministic
JSON or Markdown.

```console
aegis arsenal audit --json reports/arsenal-audit.json \
  --markdown reports/arsenal-audit.md
```

An invalid historical evidence chain remains visible as an integrity error but is excluded from
`EXECUTED_*` coverage. Current state and last verified execution are reported separately.

## Isolated fixture exercises

Fixture exercises use `LOCAL_FIXTURE_ONLY` authorization. The signature/grant verifier rejects any
non-loopback destination for this class. Every exercise follows:

```text
capability → prerequisites → MissionPlan → PolicyEngine → signed ExecutionGrant
→ registered canonical executor → immutable evidence → coverage projection
```

Run the deterministic 16-case AI boundary lab:

```console
aegis arsenal exercise \
  --capability fixture:ai/llm-security-boundary \
  --json reports/llm-fixture-validation.json
```

Run a real installed scanner against paired positive and negative local fixtures:

```console
aegis arsenal exercise --capability tool:semgrep/code
aegis arsenal exercise --all-fixture-tools --json reports/tool-fixture-validation.json
```

Missing or unhealthy binaries remain `BACKEND_UNHEALTHY`; they do not become detector misses or
successful executions. A tool run records fixture detection and negative-control behavior
separately from whether its process completed correctly.

Production coverage writes require:

```console
AEGIS_PRODUCTION=1
AEGIS_ARSENAL_COVERAGE_BACKEND=postgresql
AEGIS_ARSENAL_COVERAGE_DB_URL=postgresql://...
```

SQLite is a development/test inspection backend only. A coverage-ledger outage does not rewrite a
canonical runtime result: the evidence run remains valid and the projection is explicitly marked
`COVERAGE_RECORDING_DEGRADED`.

## AI result semantics

Each lab case emits independent `model_behavior_verdict` and `system_boundary_verdict` fields. An
unsafe model response that is blocked by policy/grant/evidence controls is reported as `UNSAFE` +
`PRESERVED`; it is not hidden and it is not an architecture bypass. The lab uses memory, RAG,
environment/tool, and cross-user canaries, includes multi-turn persistence and attempted evidence
forgery, and never submits a finding.

`AI/LLM SECURITY VALIDATION PASS` means all deterministic system-boundary oracles were preserved,
there were zero P0 bypasses, evidence integrity held, and no automatic submission occurred. It does
not mean a model is always safe and is not evidence of authorized-real AI pentest coverage.

## Authorized-real exercises

Local fixture authorization can never be promoted into real authorization. Authorized-real
coverage must originate from a fresh current program snapshot and typed permission, compile through
the existing production campaign runtime, and retain the exact PolicyEngine decision, signed grant,
asset, task, and immutable evidence references. Human review is required before a canonical finding
ID can receive `EXECUTED_FINDING` credit.
