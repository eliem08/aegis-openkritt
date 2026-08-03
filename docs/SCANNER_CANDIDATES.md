# Verified repository-scanner candidates

Validated on 2026-08-03 after operator approval of tool licensing. These are
immutable container artifacts, not yet entries in the active production scanner
lock. Promotion requires a bounded adapter, golden output fixture, schema-drift
quarantine, and a live authorized-lab run.

| Tool | Version | License | Verified image | Strength to adopt | Promotion status |
|---|---:|---|---|---|---|
| Semgrep | 1.164.0 | LGPL-2.1 | `docker.io/semgrep/semgrep@sha256:207983631beecdbe7fa29196c7f4a7a5f29033933cdb76c687ce4a672e07618d` | Language-aware structural rules, taint findings, source locations, data-flow traces | image/version verified; JSON/SARIF document adapter pending |
| Gitleaks | 8.30.1 | MIT | `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` | High-signal secret/history detection, composite rules, stable fingerprints | image/version verified; secret-safe JSON/SARIF adapter pending |
| OSV-Scanner | 2.4.0 | Apache-2.0 | `ghcr.io/google/osv-scanner@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475` | Lockfile/SBOM vulnerability matching, reachability-aware results, offline database mode | image/version verified; JSON document adapter and offline DB pin pending |

## Verified evidence

- Each tag was pulled from the repository documented by its upstream project.
- Docker reported and retained the immutable registry digest shown above.
- Executing each image by digest returned the expected embedded version.
- No image was run against a target or repository during verification.

## Required implementation work

1. Add bounded document-output support to the adapter pipeline. Existing adapters
   stream JSON Lines; these scanners emit whole JSON or SARIF documents.
2. Reject unknown schema versions and quarantine partial/malformed output.
3. Never persist raw secret values from Gitleaks. Emit only rule, redacted path,
   line, commit, and stable fingerprint into the sensitive-data quarantine flow.
4. Disable Semgrep telemetry, remote configuration, login, and auto-update. Use
   only an approved, commit-pinned rule bundle.
5. Run OSV-Scanner with a pinned offline database when target policy forbids
   dependency metadata egress; remediation commands remain disabled.
6. Execute all three in non-root, read-only, no-target-egress containers with
   CPU, memory, process, output, and wall-clock caps.
7. Capture golden fixtures from these exact digests, then promote the entries to
   `secrets/scanner-releases.lock.json` only after the adapters and live lab pass.

Until those gates pass, leaving the active release lock empty is intentional and
production readiness must continue to report scanner execution as unavailable.
