# Aegis arsenal audit

Generated: `2026-08-27T21:37:30.633396+00:00`

## Metrics

- `implemented_capability_count`: `174`
- `backend_healthy_count`: `1`
- `fixture_executable_denominator`: `71`
- `fixture_executed_count`: `0`
- `authorized_real_executed_count`: `0`
- `fixture_execution_coverage`: `0.0`
- `authorized_real_execution_coverage`: `None`
- `authorized_real_eligible_denominator`: `None`
- `verified_pass_count`: `0`
- `verified_finding_count`: `0`
- `blocked_by_policy_count`: `0`
- `waiting_prerequisite_count`: `1`
- `unavailable_count`: `173`
- `not_implemented_count`: `0`
- `backend_unhealthy_count`: `0`

## Capability matrix

| Capability | Implemented | Current state | Backend healthy | Last verified | Evidence |
|---|---:|---|---:|---|---|
| `adapter:gau/passive-discovery` | yes | UNAVAILABLE | no | never | `` |
| `adapter:gitleaks/passive-discovery` | yes | UNAVAILABLE | no | never | `` |
| `adapter:http-probe/passive-discovery` | yes | UNAVAILABLE | no | never | `` |
| `adapter:jsluice/passive-discovery` | yes | UNAVAILABLE | no | never | `` |
| `adapter:katana/passive-discovery` | yes | UNAVAILABLE | no | never | `` |
| `adapter:osv-scanner/passive-discovery` | yes | UNAVAILABLE | no | never | `` |
| `adapter:semgrep/passive-discovery` | yes | UNAVAILABLE | no | never | `` |
| `adapter:subfinder/passive-discovery` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:asset-triage` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:authorization-matrix` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:binary-triage` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:bundle-unpack` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:contract-pattern-review` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:contract-static-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:dependency-extraction` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:dns-enumeration` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:embedded-secret-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:iam-policy-review` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:mass-assignment` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:metadata-endpoint-exposure` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:object-reference-probe` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:openapi-ingest` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:output-handling-review` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:passive-certificate-transparency` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:prompt-injection-suite` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:public-blob-review` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:public-bucket-review` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:rate-limit-check` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:security-headers` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:service-identification` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:source-scanner-sweep` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:subdomain-takeover` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:system-prompt-extraction` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:tls-inspection` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:tool-abuse-chain` | yes | UNAVAILABLE | no | never | `` |
| `asset-lane:virtual-host-discovery` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-agent-permission-audit/agent-tool-permission-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-artifact-diff/authorized-mobile-release-diff` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-asset-classifier/deterministic-asset-classification` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-firmware-arch/firmware-architecture-detection` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-github-org/github-org-authorized-inventory` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-github-org/github-org-public-inventory` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-gitlab-group/gitlab-group-authorized-inventory` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-gitlab-group/gitlab-group-public-inventory` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-memory-poisoning/agent-memory-poisoning-regression` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-model-provenance/model-provenance-and-hash-ledger` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-package-registry/public-package-metadata` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-rag-boundary/rag-retrieval-trust-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:aegis-store-metadata/public-listing-metadata` | yes | UNAVAILABLE | no | never | `` |
| `asset:angr/binary-control-flow-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:apktool/android-resource-and-manifest-decode` | yes | UNAVAILABLE | no | never | `` |
| `asset:azurehound/azure-entra-relationship-collection` | yes | UNAVAILABLE | no | never | `` |
| `asset:bandit/python-security-static-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:binwalk/firmware-structure-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:brakeman/rails-security-static-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:capa/binary-capability-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:checkov/container-image-policy-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:checkov/iac-cicd-and-container-policy-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:class-dump/objective-c-interface-recovery` | yes | UNAVAILABLE | no | never | `` |
| `asset:cloudsplaining/aws-iam-risk-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:codeql/cross-file-dataflow` | yes | UNAVAILABLE | no | never | `` |
| `asset:dnsx/dns-resolution-and-wildcard-filtering` | yes | UNAVAILABLE | no | never | `` |
| `asset:echidna/smart-contract-property-fuzzing` | yes | UNAVAILABLE | no | never | `` |
| `asset:electron-asar/electron-package-extraction` | yes | UNAVAILABLE | no | never | `` |
| `asset:firmadyne/firmware-emulation-fallback` | yes | UNAVAILABLE | no | never | `` |
| `asset:firmae/firmware-emulation` | yes | UNAVAILABLE | no | never | `` |
| `asset:floss/static-string-deobfuscation` | yes | UNAVAILABLE | no | never | `` |
| `asset:foundry/smart-contract-fuzz-and-invariant-tests` | yes | UNAVAILABLE | no | never | `` |
| `asset:frida/android-runtime-instrumentation` | yes | UNAVAILABLE | no | never | `` |
| `asset:frida/ios-runtime-instrumentation` | yes | UNAVAILABLE | no | never | `` |
| `asset:garak/llm-security-probing` | yes | UNAVAILABLE | no | never | `` |
| `asset:ghidra/headless-binary-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:gitleaks/git-secret-detection` | yes | UNAVAILABLE | no | never | `` |
| `asset:gosec/go-security-static-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:grpcurl/grpc-service-introspection` | yes | UNAVAILABLE | no | never | `` |
| `asset:grype/artifact-vulnerability-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:grype/container-image-vulnerability-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:httpx/http-service-enrichment` | yes | UNAVAILABLE | no | never | `` |
| `asset:jadx/android-decompile` | yes | UNAVAILABLE | no | never | `` |
| `asset:katana/scoped-endpoint-crawl` | yes | UNAVAILABLE | no | never | `` |
| `asset:kics/iac-security-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:kubescape/kubernetes-posture-and-runtime-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:mitmproxy/authorized-http-traffic-capture` | yes | UNAVAILABLE | no | never | `` |
| `asset:mobsf/rest-static-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:modelscan/serialized-model-safety-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:mythril/evm-symbolic-execution` | yes | UNAVAILABLE | no | never | `` |
| `asset:naabu/bounded-port-discovery` | yes | UNAVAILABLE | no | never | `` |
| `asset:nmap/bounded-service-fingerprinting` | yes | UNAVAILABLE | no | never | `` |
| `asset:npm/npm-dependency-audit` | yes | WAITING_FOR_PREREQUISITE | yes | never | `` |
| `asset:nuclei/signed-safe-template-validation` | yes | UNAVAILABLE | no | never | `` |
| `asset:objection/android-runtime-exploration` | yes | UNAVAILABLE | no | never | `` |
| `asset:objection/ios-runtime-exploration` | yes | UNAVAILABLE | no | never | `` |
| `asset:openssf-scorecard/repository-supply-chain-posture` | yes | UNAVAILABLE | no | never | `` |
| `asset:osv-scanner/dependency-vulnerability-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:otool/ios-macos-load-command-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:pefile/pe-structure-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:pip-audit/python-dependency-vulnerability-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:playwright/authenticated-browser-traffic-learning` | yes | UNAVAILABLE | no | never | `` |
| `asset:promptfoo/ai-red-team-evaluation` | yes | UNAVAILABLE | no | never | `` |
| `asset:prowler/aws-security-posture` | yes | UNAVAILABLE | no | never | `` |
| `asset:prowler/azure-security-posture` | yes | UNAVAILABLE | no | never | `` |
| `asset:pyrit/generative-ai-risk-identification` | yes | UNAVAILABLE | no | never | `` |
| `asset:restler/stateful-openapi-sequence-testing` | yes | UNAVAILABLE | no | never | `` |
| `asset:rizin/binary-reverse-engineering` | yes | UNAVAILABLE | no | never | `` |
| `asset:roadtools/entra-identity-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:rustscan/bounded-fast-port-prefilter` | yes | UNAVAILABLE | no | never | `` |
| `asset:schemathesis/graphql-schema-guided-testing` | yes | UNAVAILABLE | no | never | `` |
| `asset:schemathesis/schema-guided-api-testing` | yes | UNAVAILABLE | no | never | `` |
| `asset:scoutsuite/aws-attack-surface-audit` | yes | UNAVAILABLE | no | never | `` |
| `asset:scoutsuite/azure-attack-surface-audit` | yes | UNAVAILABLE | no | never | `` |
| `asset:semgrep/source-static-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:skopeo/container-registry-metadata` | yes | UNAVAILABLE | no | never | `` |
| `asset:slither/solidity-vyper-static-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:spotbugs/java-bytecode-static-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:ssh-audit/ssh-configuration-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:subfinder/passive-subdomain-enumeration` | yes | UNAVAILABLE | no | never | `` |
| `asset:syft/artifact-sbom` | yes | UNAVAILABLE | no | never | `` |
| `asset:syft/container-image-sbom` | yes | UNAVAILABLE | no | never | `` |
| `asset:testssl-sh/tls-configuration-analysis` | yes | UNAVAILABLE | no | never | `` |
| `asset:trivy/container-image-security-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:trivy/filesystem-security-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:web-ext/browser-extension-structure-lint` | yes | UNAVAILABLE | no | never | `` |
| `asset:websocat/websocket-protocol-observation` | yes | UNAVAILABLE | no | never | `` |
| `asset:yara/approved-rule-binary-scan` | yes | UNAVAILABLE | no | never | `` |
| `asset:zizmor/github-actions-security-audit` | yes | UNAVAILABLE | no | never | `` |
| `fixture:ai/llm-security-boundary` | yes | UNAVAILABLE | no | never | `` |
| `hunter:auth_object_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:auth_role_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:auth_tenant_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:business_state_combination` | yes | UNAVAILABLE | no | never | `` |
| `hunter:cache_key_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:cache_private_shared` | yes | UNAVAILABLE | no | never | `` |
| `hunter:coverage_state_fuzzing` | yes | UNAVAILABLE | no | never | `` |
| `hunter:deep_link_trust_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:exploit_capability_chain` | yes | UNAVAILABLE | no | never | `` |
| `hunter:graphql_authorization_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:grpc_authorization_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:idempotency_key_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:js_route_recovery` | yes | UNAVAILABLE | no | never | `` |
| `hunter:js_source_map_recovery` | yes | UNAVAILABLE | no | never | `` |
| `hunter:mobile_backend_correlation` | yes | UNAVAILABLE | no | never | `` |
| `hunter:oauth_trust_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:partial_commit_verification` | yes | UNAVAILABLE | no | never | `` |
| `hunter:post_error_state_check` | yes | UNAVAILABLE | no | never | `` |
| `hunter:postmessage_trust_analysis` | yes | UNAVAILABLE | no | never | `` |
| `hunter:race_synchronized_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:recon_analytics_correlation` | yes | UNAVAILABLE | no | never | `` |
| `hunter:recon_ct_clustering` | yes | UNAVAILABLE | no | never | `` |
| `hunter:recon_vhost_inference` | yes | UNAVAILABLE | no | never | `` |
| `hunter:recovery_state_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:retry_state_verification` | yes | UNAVAILABLE | no | never | `` |
| `hunter:session_invalidation_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:ssrf_async_callback` | yes | UNAVAILABLE | no | never | `` |
| `hunter:ssrf_redirect_dns_behavior` | yes | UNAVAILABLE | no | never | `` |
| `hunter:ssrf_url_consumer` | yes | UNAVAILABLE | no | never | `` |
| `hunter:upload_workflow_differential` | yes | UNAVAILABLE | no | never | `` |
| `hunter:web_cache_deception` | yes | UNAVAILABLE | no | never | `` |
| `hunter:websocket_state_differential` | yes | UNAVAILABLE | no | never | `` |
| `tool:bandit/code` | yes | UNAVAILABLE | no | never | `` |
| `tool:brakeman/code` | yes | UNAVAILABLE | no | never | `` |
| `tool:checkov/deps` | yes | UNAVAILABLE | no | never | `` |
| `tool:detect-secrets/secrets` | yes | UNAVAILABLE | no | never | `` |
| `tool:gitleaks/secrets` | yes | UNAVAILABLE | no | never | `` |
| `tool:gosec/code` | yes | UNAVAILABLE | no | never | `` |
| `tool:grype/deps` | yes | UNAVAILABLE | no | never | `` |
| `tool:mythril/contract` | yes | UNAVAILABLE | no | never | `` |
| `tool:njsscan/code` | yes | UNAVAILABLE | no | never | `` |
| `tool:osv-scanner/deps` | yes | UNAVAILABLE | no | never | `` |
| `tool:psalm/code` | yes | UNAVAILABLE | no | never | `` |
| `tool:retire-js/deps` | yes | UNAVAILABLE | no | never | `` |
| `tool:semgrep/code` | yes | UNAVAILABLE | no | never | `` |
| `tool:slither/contract` | yes | UNAVAILABLE | no | never | `` |
| `tool:trivy/deps` | yes | UNAVAILABLE | no | never | `` |
| `tool:trivy/secrets` | yes | UNAVAILABLE | no | never | `` |
