# The learning loop — how the system auto-improves

The platform learns from outcomes **without any model fine-tuning**. Every human
verdict on a finding is recorded, and two mechanisms read that record and update
themselves automatically as verdicts accumulate.

```
findings ──▶ review console ──▶ human verdict ──▶ OutcomeStore
                  ▲                                   │
                  │                    ┌──────────────┴───────────────┐
                  │                    ▼                              ▼
                  │              Calibration priors            Retrieval memory
                  │           (rerank candidates)         (few-shot for the planner)
                  └───────────────────┴──────────────────────────────┘
```

## What "learning" means here (and what it doesn't)

It is **not** weight training — DeepSeek/Claude are used as-is. Learning is:

1. **Calibration (deterministic).** `aegis.learn.Calibration` turns verdicts into
   per-detector and per-CWE **precision priors** (Laplace-smoothed: true detections
   vs. false positives). Those priors scale a candidate's ranking, so a source that
   keeps producing false positives sinks and a reliable one rises. It reorders and
   annotates (`learned_prior`) — it never drops a finding.
2. **Retrieval memory (in-context).** `aegis.learn.learned_context` /
   `PlannerKnowledge` recall the most relevant judged findings (confirmed and
   false-positive) and inject them into the DeepSeek planner's prompt, so it plans
   conditioned on what actually panned out. The memory grows on its own.

## The loop in practice

- **Record a verdict:** `POST /ui/feedback`
  `{ "detector": "...", "cwe": "CWE-841", "verdict": "confirmed" | "false_positive" | "duplicate" }`.
  Returns the running count and the updated `learned_prior` for that detector/CWE.
- **Ranking updates immediately:** `GET /ui/review` and the upload path build the
  console with the current calibration, so the order reflects everything learned so
  far. A brand-new store is neutral (prior 0.5 → factor 1.0), so nothing changes
  until real feedback exists.
- **The planner updates:** construct `LLMPlanner(client, knowledge=PlannerKnowledge(store))`;
  its prompt then carries `learned_from_past_outcomes` with confirmed vs.
  false-positive examples and the prior precision.

## Closing the loop with real HackerOne outcomes

Human review verdicts are one teacher; the program's own resolution is the ground
truth. `aegis.learn.hackerone_sync` folds that in, in two steps:

1. **Link a submission:** `POST /ui/submission`
   `{ "report_id": "5551", "detector": "...", "cwe": "CWE-841" }` — call this when
   you submit a report, so its eventual resolution is attributed to the finding that
   produced it (`SubmissionLedger`).
2. **Sync outcomes:** `POST /ui/hackerone-sync` reads the states of your submitted
   reports (`GET /v1/hackers/me/reports`, read-only) and records verdicts:
   `resolved → confirmed`, `duplicate → duplicate`, `not-applicable`/`spam →
   false_positive`. Non-decisive states (triaged, informative, needs-more-info, …)
   are left pending. It is **idempotent per report** — re-syncing never double-counts,
   and a report that only becomes decisive later is recorded once, then.

So a detector whose reports keep getting **resolved** rises in the ranking and in the
planner's few-shot memory; one whose reports keep coming back **not-applicable**
sinks — learned from real bounty results, automatically. This path only *reads*
HackerOne; it never submits or changes anything there.

## Persistence & safety

- Set `AEGIS_LEARN_DB=<path>` to persist what's learned across restarts; unset keeps
  it in memory.
- Only short, **redacted** summaries are stored — never raw payloads or secrets.
- Calibration is a *prior*, never a gate: verification still decides what is real,
  and submission stays human-approved. A hallucinating or prompt-injected model
  cannot widen scope or actions through this path — the deterministic guard in the
  planner re-checks every proposed action regardless of what the memory suggests.
