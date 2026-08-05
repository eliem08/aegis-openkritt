# Aegis architecture — what actually runs vs. what's experimental

This project is large (33 subpackages). This map is the honest split between the code that
the **working autonomous hunt** exercises today and the **experimental/operator-gated**
subsystems that exist but are not driven by it. Read this before assuming a module is load-
bearing.

## LIVE — the working autonomous code/contract hunt

The value path, exercised end-to-end and covered by tests:

- **`ai/`** — the hunt brain. Entry points: `auto_hunt` / `auto_hunt_run` (the 24/7 loop),
  `hunt_repo` / `hunt_contract` (single-target CLIs). Pipeline per target:
  clone (`repo_clone`) → ensemble generate (`repo_hunt` + `agents/runner`, primed by
  `knowledge_retrieval`, `taint`, `focus`) → fold arm's-length **scanners** (`tool_bridge`
  + `tool_registry`, 14 tools) and **skills** (`skill_bridge` + `skill_runner`, prompt-only)
  → **corroboration** → **validator** (`code_validation` / `report_validation`) →
  **reachability gate** (`reachability`) → **retired-repo filter** (`repo_status`) →
  enrichment (`enrich`) + economics (`economics`, `pricing`, `cost`) → PoC scaffold
  (`poc_harness`). Signal helpers: `corroboration`, `negative_examples`, `regression`,
  `fresh_commits`, `fresh_watch`, `briefing`.
- **`api/`** — FastAPI control plane + the operations dashboard (`/ui/hunt-console`,
  `/ui/briefing`, `/ui/cost`, `/ui/autohunt*`).
- **Supporting, imported by the above:** `knowledge` (report corpus), `learn`
  (calibration/outcomes), `ingest` (HackerOne Hacker API, read-only), `policy`
  (authorization/signing), `model_gateway` + `model` (usage/pricing types), `observ`
  (logging), `report`, `integrations` (open·kritt bridge, arm's-length), `graph`, `env`.

## EXPERIMENTAL — built, not wired into the autonomous hunt

These exist (some fully, some partial) but the code-hunt does **not** drive them. They are
operator-gated (they hit live third parties) or earlier scaffolding. Treat as not-load-
bearing; do not assume they are exercised.

- **Web lane (active scanning of live hosts):** `active/`, `detect/`, `oast/`,
  `adapters/`, `web_lane.py`. Assembled but intentionally not auto-run — active traffic at
  third parties requires per-program authorization (see the web-scope audit). `web_lane`'s
  `WebLaneRunner` is referenced only by its own test.
- **Distributed/ops scaffolding:** `coord/`, `netgate/`, `orchestrator/`, `scheduler/`,
  `gateway/`, `egress/`, `production/`, `supply/`, `browser/`, `sensitive/`.
- **Truly unreferenced right now (0 non-self imports):** `active/`, `browser/`, `egress/`,
  `production/`.

## Guidance

- Changing **LIVE** modules → run the suite; they're on the money path.
- Touching **EXPERIMENTAL** modules → they won't affect the hunt, but they also aren't
  guaranteed to work; verify before relying on them.
- New hunt features belong in `ai/` and surface through `api/`.
- Before deleting an experimental subpackage, confirm no test imports it (several have
  their own tests that would break); prefer archiving over deletion.
