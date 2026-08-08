# Active detector authorization boundary

`aegis.active` is integrated as a planning capability, not as an autonomous live-attack bypass.

The production source-review hunt may infer that SSRF, GraphQL, authorization-differential, path-normalization, CORS, redirect or error-disclosure validation could add evidence. Such a source finding creates only a canonical `AgentProposal` intent.

A live detector still requires all of the following before execution:

1. current target authorization;
2. discovered concrete routes/assets rather than invented endpoints;
3. a detector plan derived from those assets;
4. network authorization;
5. state-change authorization;
6. sufficient request/cost budget;
7. explicit human approval.

`ProposalPolicy` evaluates those requirements centrally. The ordinary source-review envelope has no live-network authority, so active intents are vetoed by default.

Local Docker reproduction is separate from target-network testing. It remains explicitly opt-in with `AEGIS_ALLOW_REPRO=1`, is localhost-only, and is treated as a controlled local state change.
