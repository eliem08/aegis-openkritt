# Aegis Products

One engine, seven product surfaces. The `aegis.products` layer turns the hunt engine (the
15-scanner arsenal + LLM ensemble + reduction/corroboration funnel + local-only reproduction) into
named products you can run three ways: the **CLI**, the **HTTP job API**, and the **operator
console**.

> **Honesty contract.** A candidate is an unverified hypothesis. `confirmed` means the citation
> validator matched the claim against pinned source; **`reproduced` is set only by real local
> execution of a deterministic oracle — never by model confidence.** Nothing is submitted anywhere.
> Every product result carries this note.

---

## The seven products

### Group A — sell the finder (your own code)
| Product | What it does |
|---|---|
| **Repo Autopilot** | Continuous governed review of a repo you own; ships only `confirmed`/`reproduced` findings. `reproduced_only` mode is safe to auto-file as tickets. |
| **PR Gatekeeper** | Reviews only the files a PR changed; emits SARIF and a pass/fail gate (blocks when a finding lands in the diff). |
| **Standing Red Team** | Scheduled autopilot that reports only what is *newly* exploitable versus the previous run. |

### Group B — sell the proof (any finding)
| Product | What it does |
|---|---|
| **Proof of Vuln** | Validates a finding against source and, when the checkout runs locally, reproduces it against a deterministic oracle. |
| **Proof of Fix** | Reproduces on the vulnerable checkout (must trigger) and the fixed checkout (must not) → `fix_confirmed` / `still_vulnerable` / `fix_unproven`. |
| **Slop Filter** | Runs another tool's findings through the validator and splits them into `kept` vs `killed`. |
| **Bounty Triage** | For program owners: clusters duplicate submissions, validates each unique report, ranks the queue. |

---

## Evidence model

Every finding carries an evidence stage derived from its own verdicts — never asserted:

```
candidate → source_supported → runtime_observed → oracle_passed → locally_reproduced
          → independently_verified → human_approved → submission_ready
```

- **detected** — a raw scanner/LLM candidate, not yet validated.
- **confirmed** — the citation validator matched the claim against pinned source.
- **reproduced** — real local execution triggered a deterministic oracle (opt-in, local-only).
- **refuted** — the validator rejected it.

---

## Run it — CLI

```bash
# B — proof / validation (operate on findings you supply)
aegis products proof-vuln  --finding finding.json --repo-dir ./checkout
aegis products proof-fix   --finding finding.json --vuln-dir ./vuln --fixed-dir ./fixed
aegis products slop-filter --findings other_tool.json --repo-dir ./checkout
aegis products triage      --reports inbox.json --no-validate

# A — finders (own code; invoke the LLM+scanner engine)
aegis products autopilot   --repo owner/repo --repo-dir ./checkout --reproduced-only
aegis products pr-gate     --repo owner/repo --changed-from changed.txt --sarif out.sarif
aegis products redteam     --repo owner/repo --previous-ids last_run_ids.json
```

Each command prints a JSON `ProductResult` (findings ranked reproduced → confirmed → detected, plus
stats and the honesty note). `pr-gate` exits non-zero when the gate blocks — drop it straight into
CI.

**Requirements.** The finder commands need the engine configured (an LLM key via `DEEPSEEK_API_KEY`
or `OPENROUTER_API_KEY`, `git`, and installed scanners — use the `aegis-arsenal` image for the full
15-tool set). Reproduction is opt-in and local-only: `AEGIS_ALLOW_REPRO=1` and a `docker-compose` in
the checkout. The proof commands that only validate/dedupe need far less.

---

## Run it — HTTP job API

Product runs can take minutes, so the API is job-based. Every route needs at least an **agent**
bearer token and is tenant-scoped.

```bash
# submit -> 202 + job id
curl -sX POST http://localhost:8000/products/triage \
  -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"reports": [ ... ], "validate_reports": false}'
# {"job_id":"…","status":"queued", ...}

# poll
curl -s http://localhost:8000/products/jobs/<job_id> -H "authorization: Bearer $TOKEN"
# {"status":"completed","result":{ "findings":[…], "stats":{…}, "honesty":"…" }}

# list this tenant's jobs
curl -s http://localhost:8000/products/jobs -H "authorization: Bearer $TOKEN"
```

Endpoints: `POST /products/{autopilot,pr-gate,redteam,proof-vuln,proof-fix,slop-filter,triage}` and
`GET /products/jobs[/{id}]`.

---

## Run it — operator console

Open **`/ui/products`** on the control plane. A self-contained console (no external assets): pick a
product, fill the form, paste your bearer token, and Run — it submits a job, polls it live, and
renders stat tiles and a findings table with evidence badges. Light/dark aware.

```bash
# stand up the control plane (the arsenal image bundles the full scanner set)
docker run --rm -p 8000:8000 --env-file .env aegis-arsenal
# then browse http://localhost:8000/ui/products
```

---

## Honest limits (unchanged by this layer)

The products are delivery surfaces over the real engine; they do not change what it can find:

- **Finder recall is model- and selection-dependent.** A weak model finds little; use a strong
  model and a wide file selection for real recall.
- **Reproduction covers a slice** — HTTP-observable bugs in a locally-runnable app, opt-in. Findings
  with no runnable instance stay `confirmed` at best, never `reproduced`.
- **`confirmed` is an LLM validator's agreement**, which has a real false-positive rate. Treat
  confirmed findings as candidates worth human review, not proven bugs.
- **Nothing is auto-submitted.** Submission is always a human decision.

The single highest-leverage next step is empirical, not more surface area: point Proof of Vuln /
Repo Autopilot at a design partner's real code with a strong model and land one reproduced,
independently-verified finding.
