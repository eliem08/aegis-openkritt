# Aegis / open·kritt — Engineering Review & Honest Scorecard

**Date:** 2026-08-07  
**Branch:** `agent/aegis-10x-p0`  
**PR:** #2  
**Review:** Claude Code implementation + follow-up engineering review

> This review deliberately separates detector regression, vulnerability reproduction, and
> real-world bounty performance. No scanner match is called a reproduced vulnerability unless it
> passes Aegis's reproduction/evidence lifecycle.

---

## 0. Bottom line

**This is not yet a 10/10 system.** It is a strong engineering platform whose core commercial
value proposition still needs real-world empirical proof.

- **Engineering platform:** strong policy, authorization, evidence boundaries, agent orchestration,
  scanner adapters, persistent learning, and a large green test suite.
- **Autonomous bounty profitability:** still unproven until Aegis repeatedly produces genuine,
  locally reproduced, independently verified findings and records accepted bounty outcomes.

The next gains should come from empirical validation and execution hardening, not feature count.

---

## A. What PR #2 actually adds

| Change | Status | Evidence |
|---|---|---|
| Project identity coherent | Done | package `aegis`, version `0.7.0` |
| Aegis-Bench detector regression harness | Done | `src/aegis/bench/` + tests |
| Real scanner invocation | Done for canonical CI lane | pinned Semgrep through the existing tool bridge |
| Vulnerable/clean negative-control pairs | Done | 10 canonical pairs |
| Two bundled-rule false positives fixed | Done | WordPress prepared-query and safe-upload-name cases |
| Lint promoted to merge gate | Done | Ruff `F/E9/I` |
| Detector benchmark promoted to merge gate | Done | canonical positives must all fire; clean twins must remain clean |
| Detection/reproduction semantics separated | Done | static hits stay `detected`; `reproduced` remains zero until runtime reproduction |

---

## B. What the benchmark currently proves

The canonical corpus contains **10 vulnerable/clean pairs** targeting Aegis's bundled Semgrep
rules. In Linux CI, the pinned Semgrep lane currently measures:

```text
cases 10 | detected 10 | missed 0 | false-positives 0
recall 1.00 | precision 1.00 | fp_rate 0.00
```

This proves that the current pinned Semgrep version and bundled rules correctly recognize these
canonical vulnerable patterns and do not flag their paired negative controls.

It does **not** prove:

- 100% precision on arbitrary third-party repositories;
- 100% recall on real vulnerability corpora;
- runtime exploitability;
- local vulnerability reproduction;
- bounty acceptance or profitability;
- full external-scanner arsenal validation in CI.

The CI benchmark is intentionally a **detector regression/sanity gate**.

---

## C. Why detection is not reproduction

Aegis's evidence model treats these stages differently:

```text
candidate
→ source_supported
→ runtime_observed
→ oracle_passed
→ locally_reproduced
→ independently_verified
→ human_approved
→ submission_ready
```

A Semgrep match on a labeled fixture is only detector evidence. PR #2 therefore maps benchmark
results into the canonical `BenchmarkRun` with:

```text
detected = detector true positives
missed = detector false negatives
false_positives = clean-twin hits
reproduced = 0
```

`BenchmarkRun.detector_precision` and `BenchmarkRun.detector_recall` describe detector quality.
Existing reproduction/acceptance economics continue to use actual reproduced findings only.

This prevents detector tests from inflating reproduction rate, cost-per-reproduced, or release
metrics.

---

## D. CI reproducibility

The canonical detector job pins:

```text
semgrep==1.172.0
```

instead of installing floating `latest` Semgrep.

The self-authored canonical corpus is now a **zero-regression gate**:

```text
all vulnerable fixtures must be detected
zero clean twins may be flagged
```

This strictness is appropriate for a small regression corpus designed around Aegis's own rules.
Future real-world/CVE benchmarks should use separately justified thresholds rather than inheriting
this perfect-corpus requirement.

---

## E. Current engineering assessment

| Dimension | Assessment |
|---|---|
| Policy / authorization / kill switch / scope / budgets | Strong and real |
| Human approval boundary | Strong and real |
| Canonical detector regression | Real and CI-gated |
| Detector-vs-reproduction semantics | Correctly separated |
| Cost tracking / budget enforcement | Real |
| Test suite / CI | Strong |
| Tooling breadth | Broad, but external tools vary by runtime/platform |
| LLM analysis quality | Real pipeline, insufficiently benchmarked |
| Real-world detector quality | Not yet established |
| End-to-end reproduced bounty findings | Not yet established |
| Realized bounty profitability | Not yet established |

---

## F. Highest-leverage next slices

1. **Real-CVE ground truth.** Add pinned vulnerable commits and their fixed versions from
   permissively licensed projects, so Aegis is evaluated on code it did not author.
2. **One full reproduction loop.** Take a genuine local vulnerability through deterministic oracle,
   local reproduction, independent verification, and evidence bundle generation.
3. **LLM evaluation.** Score the model-analysis pipeline independently of deterministic scanners.
4. **External scanner integration CI/nightly.** Pin and exercise additional important scanners in
   isolated integration jobs rather than implying the Semgrep CI lane validates the whole arsenal.
5. **Outcome evidence.** Feed real accepted/rejected/duplicate bounty outcomes into the economic
   learner and report realized net value.

---

## G. Honest verdict

PR #2 materially improves correctness because it converts detector quality from an assertion into a
measured regression signal, found two real false-positive rule defects, and now keeps static
detection metrics separate from vulnerability reproduction.

The benchmark is useful precisely because its claim is narrow:

> **Pinned Semgrep + bundled Aegis rules pass the canonical 10-pair regression corpus with no
> clean-twin false positives.**

Anything stronger requires additional empirical evidence.
