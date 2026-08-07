# Aegis / open·kritt — Engineering Review & Honest Scorecard

**Date:** 2026-08-07  ·  **Branch:** `agent/aegis-10x-p0`  ·  **PR:** #2  ·  **Reviewer:** Claude (Opus 4.8)

> This document was requested with an explicit constraint: *do not claim the repo is 10/10, do
> not invent benchmark numbers, do not claim a tool is integrated if only its name exists in a
> registry, do not claim vulnerabilities are found unless actually reproduced.* Every number below
> is measured; every "real vs. contract" call is grounded in code I read or ran.

---

## 0. Bottom line

**This is NOT a 10/10 system.** It is a genuinely well-engineered *platform* wrapped around a core
value proposition that remains **unproven**.

- **As software engineering:** ~**7/10.** Real policy/authorization layer, real cost tracking, a
  green test suite, and — as of this session — a *measured* detector benchmark wired into CI as a
  hard gate. That is above average for a solo research platform.
- **As a "profit-generating autonomous bug finder":** ~**3/10, unproven.** Across this entire
  program it has produced **zero reproduced, submittable, real-world findings.** Every carpet-sweep
  and hunt "hit" investigated this session resolved to a false positive. There is no bounty revenue
  and no confirmed vulnerability to point at. That is the honest headline and no amount of
  green CI changes it.

The gap between those two numbers *is* the project.

---

## A. What this session actually changed (verifiable)

| Change | Status | Evidence |
|---|---|---|
| Project identity coherent | Done | `pyproject` `aegis-policy`→`aegis`, `0.3.0`→`0.7.0`; `__version__` bumped |
| **Aegis-Bench** detector benchmark | Built + unit-tested | `src/aegis/bench/`, 6 tests green; folds into existing `benchmarking.BenchmarkRun` (no parallel system) |
| Detector numbers **measured** (not asserted) | Done | Ran in the arsenal Linux image *and* in CI |
| **2 real false positives found & fixed** | Done | `php-sqli-raw-query-concat` + `upload-no-extension-allowlist`; precision **0.83 → 1.00** |
| `lint` promoted to a real CI gate | Done | ruff pinned to `F/E9/I`, passes |
| `bench` job = hard detector-signal gate | Done | CI run [31220186653](https://github.com/eliem08/aegis-openkritt/actions/runs/31220186653): all 4 jobs green |

### The measured numbers (do not extrapolate these — see §C)

Labeled corpus of **10 vulnerable/clean pairs** targeting Aegis's own bundled Semgrep rules, run
against the **real** scanners:

```
cases 10 | detected 10 | missed 0 | false-positives 0
recall 1.00 | precision 1.00 | fp_rate 0.00
```

- Reproduced twice: arsenal image (semgrep, bandit, njsscan, brakeman, gitleaks, detect-secrets,
  trivy) **and** the CI Linux runner (semgrep). Not a one-off.
- The benchmark *earned its keep on day one*: the first run measured precision 0.83 / FP-rate 0.20
  and pointed at two clean fixtures being flagged. Both were genuine rule over-breadth bugs (a
  correctly-`prepare()`d `$wpdb->query` and a server-generated safe filename), now fixed.

---

## B. Critical scorecard (whole repo)

| Dimension | Grade | Real or contract? | Note |
|---|---|---|---|
| Policy / authorization / kill-switch / scope / budget | **A−** | **Real & wired** | `PolicyEngine` (352 LoC) composes `authorization`+`budget`+`killswitch`+`scope`+`signing`; kill-switch & auth validity short-circuit first; imported across planner/api/approvals/decisions. Not stubs. |
| Human-approval boundary (no auto-submit) | **A** | **Real** | Dedicated `api/routers/approvals.py`; approval tiers/tokens in `engine.py`. Consistent with the hard rule: never auto-submit to H1/Immunefi. |
| Bundled detector rules (precision on canonical patterns) | **B+** | **Real & now measured** | 1.00/1.00 on the sanity corpus after this session's fixes. Ceiling limited by corpus size (§C). |
| Cost tracking / budget enforcement | **B** | **Real** | `cost.py` uses OpenRouter `usage.cost`; per-file `over_budget()` gate. Verified against live 402s earlier in the program. |
| Test suite + CI | **B+** | **Real** | Full suite green in the canonical `.venv`; CI matrix 3.11/3.12 + lint + bench all green with real gates. |
| Tooling breadth | **B−** | **Real but platform-limited** | The full arsenal (7 scanners) runs only in the Linux image; on the user's Windows box semgrep-core and the PHP/Ruby/Go tools do not run. Honestly reflected by the `AEGIS_BENCH_STRICT` gate. |
| LLM analysis pipeline | **C+** | **Real, unmeasured** | DeepSeek via OpenRouter works and is cost-tracked, but its precision on real repos has **no** measured ground truth. |
| Carpet sweep (24/7 scanner) | **C** | **Real, low-yield so far** | Runs, dedupes by commit, persists incrementally — but every finding this session was a false positive. |
| **Real-world bounty output** | **F** | **Contract only** | **Zero** reproduced, submittable findings to date. This is the value prop and it is unproven. |

---

## C. What remains only a contract (explicitly NOT proven)

1. **Real-world detector precision/recall.** The 1.00/1.00 is on a **10-pair corpus we authored to
   target our own rules**. It proves the rules fire on canonical patterns and stay clean on their
   matched safe twins — a **regression/sanity gate**, nothing more. It is *not* evidence of
   precision on arbitrary third-party code. Believing otherwise would be exactly the self-deception
   the benchmark exists to prevent.
2. **End-to-end "find a real bug."** No confirmed, locally-reproduced, submittable finding exists.
   The reproduction agent (`repro_agent.py`, `reproduction_first.py`) is real code but has never
   closed the loop on a genuine vulnerability in this program.
3. **Tool functioning across platforms.** "Present in the registry / binary resolves" ≠ "runs and
   produces valid findings here." True on Linux (arsenal); not true on the Windows host.
4. **LLM finding quality.** No labeled evaluation of the DeepSeek pipeline's true/false positive
   rate on real repositories.

---

## D. Verdict

- **Engineering platform:** solid and, as of this PR, more honest than it was — the detector claims
  are now *measured and gated* instead of asserted, and the benchmark immediately paid for itself by
  catching two real FPs.
- **Money-making bug finder:** still a promise. The single most important next step is not another
  feature — it is **one reproduced, real-world finding**, end to end, with evidence.

Anyone who tells you this is 10/10 because a lot of code was written is selling you the same
false positive the carpet sweep keeps generating.

---

## E. Highest-leverage next slices (prioritized)

1. **Ground truth from real CVEs.** Extend Aegis-Bench with a handful of *known-vulnerable real
   commits* (pinned SHAs) + their fixes, so recall/precision get measured against code we did *not*
   write. This is the only thing that converts §C-item-1 from contract to fact.
2. **Close one reproduction loop.** Take one plausible LLM/semgrep finding on a permissively-licensed
   local target all the way to a working local PoC + evidence bundle. One real finding > ten features.
3. **Measure the LLM pipeline.** Run the DeepSeek analyzer over the labeled corpus and report its
   own precision/recall next to the deterministic scanners.
4. **Carpet-sweep precision.** Every hit so far was an FP; add the same negative-control discipline
   (a "does this survive a clean twin?" check) before a finding is ever surfaced.

---

*Generated as part of PR #2. All measured numbers are reproducible via `python -m aegis.bench`
(real numbers require a Linux scanner environment — the arsenal image or CI; semgrep-core does not
run on Windows).*
