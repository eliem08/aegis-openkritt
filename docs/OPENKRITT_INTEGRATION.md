# open·kritt integration — arm's-length, AGPL-safe

[open·kritt](https://github.com/Kritt-ai/open-kritt) is a separate, self-hosted
AI security-research platform (workflow builder → parallel focused agents →
de-duplicated, ranked findings). Aegis integrates **with** it; it does not absorb it.

## The license constraint (why this is arm's-length)

open·kritt is licensed **AGPL-3.0**. If any open·kritt source were copied or linked
into the Aegis tree, the AGPL's copyleft would extend to *all of Aegis* — including
§13's network clause, which requires offering complete corresponding source to every
user who interacts with the combined work over a network. That is a project-wide
relicensing decision, and it is exactly the kind of thing the repo's standing rule
reserves for an explicit legal review (AGPL/GPL tools are clean-room only; see the
reference-tool policy).

So the integration is deliberately **at arm's length**:

- **No open·kritt source is vendored.** Nothing from its repo is copied into `src/`.
  The clone used to learn its data contract lives only in a scratch directory and is
  never committed.
- **We exchange only its public data contract** — the finding export (its
  `vulnerabilities` rows) and its step `output_format`. Field *names* are facts, not
  copyrightable expression.
- **open·kritt runs as its own process**, under its own AGPL obligations, which are
  the operator's responsibility (it ships its own `docker-compose.yml`). Running a
  separate AGPL program and consuming its output is not a derivative work.

If you ever *do* want to fork open·kritt into the core, that is a separate, explicit
decision that relicenses Aegis under AGPL-3.0 — do the legal review first.

## What the adapter does (`aegis.integrations.openkritt`)

Inbound — `ingest_openkritt_findings(export)`:

- Accepts a list of vulnerability rows, a wrapper dict
  (`vulnerabilities`/`results`/`findings`), a JSON string, or a path to a JSON file.
- Reads each row's `json_answer` (open·kritt's eight required keys:
  `vulnerability_type`, `file_path`, `line`, `summary`, `explanation`,
  `trigger_flow`, `malicious_input_example`, `malicious_actor`) plus the dedupe/rank
  wrapper fields, and maps it to an Aegis `Candidate`.
- Respects open·kritt's own **dedup** (`only_canonical=True` drops rows it already
  clustered as duplicates) and severity (`min_impact` floor); maps
  `vulnerability_type` → CWE.

Outbound — `to_openkritt_output_format()`: emits an open·kritt-compatible step
`output_format` so Aegis can hand it a focused task whose result maps straight back
through the ingest path.

Wired into reporting via `surface_candidates(openkritt_findings=...)`, so an external
open·kritt run flows through the **same** triage/verification pipeline as native
detectors.

## Two boundaries kept on ingest

1. **Candidate, not verdict.** An imported row is an unverified hypothesis
   (`evidence_id is None`). open·kritt's `exploitable`/rank is a *hint*; the finding
   still must pass Aegis's verification gate (differential evidence or an independent
   replay) before it can be reported.
2. **No exploit payloads surfaced.** The `malicious_input_example` key (a live
   payload) is never copied into the surfaced candidate — it stays in open·kritt for
   human review. This preserves Aegis's human-approval / no-auto-exploitation
   boundary.
