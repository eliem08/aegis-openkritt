# Verified repository-scanner candidates

Validated on 2026-08-03 after operator approval of tool licensing. These are
immutable container artifacts, not yet entries in the active production scanner
lock. Promotion requires a bounded adapter, golden output fixture, schema-drift
quarantine, and a live authorized-lab run.

| Tool | Version | License | Verified image | Strength to adopt | Promotion status |
|---|---:|---|---|---|---|
| Semgrep | 1.164.0 | LGPL-2.1 | `docker.io/semgrep/semgrep@sha256:207983631beecdbe7fa29196c7f4a7a5f29033933cdb76c687ce4a672e07618d` | Language-aware structural rules, taint findings, source locations, data-flow traces | image/version verified; strict JSON parser complete; container execution pending |
| Gitleaks | 8.30.1 | MIT | `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` | High-signal secret/history detection, composite rules, stable fingerprints | image/version verified; secret-safe JSON parser complete; container execution pending |
| OSV-Scanner | 2.4.0 | Apache-2.0 | `ghcr.io/google/osv-scanner@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475` | Lockfile/SBOM vulnerability matching, reachability-aware results, offline database mode | image/version verified; JSON parser complete; offline DB pin and container execution pending |

## Verified evidence

- Each tag was pulled from the repository documented by its upstream project.
- Docker reported and retained the immutable registry digest shown above.
- Executing each image by digest returned the expected embedded version.
- No image was run against a target or repository during verification.

## Implementation status and changes still needed

- [x] Add bounded whole-document output to the coordinator without changing
  streaming JSON Lines behavior.
- [x] Quarantine malformed documents, schema mismatches, partial Semgrep scans,
  and blocking parser diagnostics.
- [x] Add sanitized golden contracts for all three verified image versions.
- [x] Never persist Gitleaks `Secret`, `Match`, `Line`, author, email, or commit
  message values. Emit only rule, normalized path, line, commit hash, and stable
  fingerprint into the sensitive-data quarantine flow.
- [ ] Add the hardened container executor. It must run these exact image digests
  as non-root with a read-only root filesystem, temporary workspace, no target
  egress, dropped capabilities, and CPU/memory/process/output/time caps.
- [ ] Disable Semgrep telemetry, remote configuration, login, version checks, and
  auto-update; mount only an approved commit-and-digest-pinned local rule bundle.
- [x] Treat OSV exit code 1 as vulnerabilities found, not an infrastructure
  failure, while preserving failure semantics for every other non-zero exit.
- [ ] Pin an offline OSV database snapshot for egress-free dependency matching.
- [ ] Run digest-produced golden output and an authorized local vulnerable-repo
  lab through the real container executor, then promote the three entries into
  `secrets/scanner-releases.lock.json`.

Until those gates pass, leaving the active release lock empty is intentional and
production readiness must continue to report scanner execution as unavailable.
