# Jarvis runtime status

## Integrated on the live source-review path

- canonical `agentic_os.AgentProposal` / `ProposalPolicy`
- canonical evidence lifecycle through `source_supported`
- finding-level `Opportunity` expected net value
- learned-prior calibration via `JarvisStateStore`
- persistent mission scheduling
- persistent security-reasoning graph
- Skeptic model-spend gate
- enrichment model-spend gate
- local reproduction policy gate
- sequential reproduction evidence promotion
- `active/` detector intents and plans through canonical policy

## Intentionally not autonomous live execution

Active target-network probes remain proposal-only until an engagement explicitly grants network, state-change and human approval and a concrete detector plan is derived from discovered assets.

## Compatibility modules

The older `jarvis/models.py`, `jarvis/council.py` and `jarvis/economics.py` contracts remain for existing tests/importers. They are not the contract for new live integrations. Their callers should be migrated incrementally to `agentic_os` before removal.

## Still to integrate after this slice

- additional `knowledge/` corpus/planner signals into Jarvis memory
- model-gateway task/cost telemetry into the common economics feedback loop
- detect/scheduler/orchestrator lane convergence where it can be done without destabilizing the production hunt
- real bounty acceptance/duplicate/payout outcomes into durable priors
