# Aegis Jarvis Agent OS

Aegis v0.6 evolves from an AI-enhanced scanner orchestrator into an **agent-first,
evidence-led security research operating system**.

## Core rule

Agents do not directly widen scope, spend unlimited money, mutate targets, or submit
reports. Every agent produces typed proposals. A deterministic policy gate checks scope,
request budget, cost budget, network authorization, model-egress authorization, action
risk, and human approvals before scheduling.

## Council

The default council includes:

- Commander
- Policy
- Recon
- Repository Intelligence
- Attack Surface
- Static Analysis
- Authentication
- Authorization
- Business Logic
- API
- Client
- Supply Chain
- Cloud
- Invariant
- Hypothesis
- Patch/Variant
- Coverage
- Reproduction
- Evidence
- Skeptic
- Profitability
- Reporting

Specialists can use different models and tools, but the Commander remains the only
scheduler.

## Research loop

1. **Policy Agent** loads the signed program policy and scope digest.
2. **Recon / Repository / Attack Surface Agents** build the current surface.
3. **Invariant Agent** infers intended security properties.
4. **Hypothesis Agent** proposes concrete violations tied to those invariants.
5. **Coverage Agent** prioritizes unexplored or recently changed intersections.
6. **Profitability Agent** estimates duplicate-adjusted expected net value.
7. **Skeptic Agent** attempts to falsify the hypothesis.
8. **Reproduction Agent** plans deterministic validation in a disposable local lab.
9. **Evidence Agent** assembles redacted, integrity-bound evidence.
10. **Reporting Agent** may draft only after evidence and independent verification.
11. A human remains the final authority for submission.

## Memory and compounding knowledge

`AgentMemory` stores program-scoped facts and outcomes in SQLite. The system can remember:

- previously tested components;
- rejected hypotheses;
- duplicate-heavy weakness classes;
- accepted findings and payouts;
- cost history;
- coverage gaps;
- architecture changes;
- reusable vulnerability mechanisms.

Outcome feedback is used by the portfolio scheduler to allocate future research time.

## Economics

Aegis should optimize for:

`expected payout × P(valid) × P(accepted) × P(unique) × P(reproduced) - total cost`

rather than raw scanner alert count. The portfolio scheduler includes an exploration bonus
so promising but underexplored programs are not starved forever.

## Prompt-injection firewall

Repository content is always untrusted data. README files, comments, issue text, fixtures,
AGENTS files, generated files, and third-party skills must never become higher-priority
instructions. Secret-like content is blocked from external model egress even when general
egress is authorized.

## Safety boundary

This architecture is intended for authorized bug-bounty research and local reproduction.
It does not authorize destructive testing, credential abuse, stealth/evasion,
indiscriminate scanning, or autonomous submission.
