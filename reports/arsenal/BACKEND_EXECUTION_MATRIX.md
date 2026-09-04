# Backend Execution Matrix

Git SHA: `97331ee62ae558421929d2c9c5eb1848210bd576`
Source Git SHA: `97331ee62ae558421929d2c9c5eb1848210bd576`
Generated At: `2026-09-04T01:08:00.386832+00:00`
Verdict: **FULL ACTIVE SOFTWARE ARSENAL VERIFIED — MIGRATED/HARDWARE-SPECIFIC CAPABILITIES SEPARATE**

| Backend runtime | Tool | Runner | Active/Migrated | Kind | Proof Kind | Positive | Negative | State | Capabilities |
|---|---|---|---|---|---|---|---|---|---|
| `ghidra/headless` | Ghidra | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:ghidra/headless-binary-analysis |
| `angr/linux-cli` | angr | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:angr/binary-control-flow-analysis |
| `apktool/linux-cli` | apktool | `arsenal-android` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:apktool/android-resource-and-manifest-decode |
| `electron-asar/node-cli` | @electron/asar | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:electron-asar/electron-package-extraction |
| `azurehound/cloud-lab` | AzureHound | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:azurehound/azure-entra-relationship-collection |
| `bandit/linux-cli` | Bandit, bandit | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset-lane:source-scanner-sweep<br>asset:bandit/python-security-static-analysis<br>tool:bandit/code |
| `binwalk/firmware-lab` | binwalk | `arsenal-firmware` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:binwalk/firmware-structure-analysis |
| `brakeman/linux-cli` | Brakeman, brakeman | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:brakeman/rails-security-static-analysis<br>tool:brakeman/code |
| `capa/linux-cli` | capa | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:capa/binary-capability-analysis |
| `checkov/linux-cli` | Checkov, checkov | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:checkov/container-image-policy-scan<br>asset:checkov/iac-cicd-and-container-policy-scan<br>tool:checkov/deps |
| `class-dump/macos-cli` | class-dump | `arsenal-macos-ios` | migrated | EXTERNAL_TOOL | `MIGRATED_EQUIVALENT` | MIGRATED | MIGRATED | **WAITING_FOR_PREREQUISITE** | asset:class-dump/objective-c-interface-recovery |
| `cloudsplaining/cloud-lab` | Cloudsplaining | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:cloudsplaining/aws-iam-risk-analysis |
| `codeql/linux-cli` | CodeQL | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:codeql/cross-file-dataflow |
| `detect-secrets/linux-cli` | detect-secrets | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | tool:detect-secrets/secrets |
| `dnsx/network-lab` | dnsx | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:dnsx/dns-resolution-and-wildcard-filtering |
| `echidna/contract-cli` | Echidna | `arsenal-smart-contract` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:echidna/smart-contract-property-fuzzing |
| `firmadyne/qemu-lab` | Firmadyne | `arsenal-firmware` | migrated | EXTERNAL_TOOL | `MIGRATED_EQUIVALENT` | MIGRATED | MIGRATED | **WAITING_FOR_PREREQUISITE** | asset:firmadyne/firmware-emulation-fallback |
| `firmae/qemu-lab` | FirmAE | `arsenal-firmware` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:firmae/firmware-emulation |
| `floss/linux-cli` | FLOSS | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:floss/static-string-deobfuscation |
| `foundry/forge` | Foundry | `arsenal-smart-contract` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:foundry/smart-contract-fuzz-and-invariant-tests |
| `frida/device-cli` | Frida | `arsenal-android` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:frida/android-runtime-instrumentation<br>asset:frida/ios-runtime-instrumentation |
| `garak/linux-cli` | garak | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:garak/llm-security-probing |
| `gau/network-lab` | gau | `arsenal-network-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **UNAVAILABLE** | adapter:gau/passive-discovery |
| `gitleaks/linux-cli` | gitleaks | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | adapter:gitleaks/passive-discovery<br>asset-lane:source-scanner-sweep<br>asset:gitleaks/git-secret-detection<br>tool:gitleaks/secrets |
| `gosec/linux-cli` | gosec | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:gosec/go-security-static-analysis<br>tool:gosec/code |
| `grpcurl/network-lab` | grpcurl | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:grpcurl/grpc-service-introspection |
| `grype/linux-cli` | grype | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:grype/artifact-vulnerability-scan<br>asset:grype/container-image-vulnerability-scan<br>tool:grype/deps |
| `httpx/network-lab` | http-probe, httpx | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | adapter:http-probe/passive-discovery<br>asset:httpx/http-service-enrichment |
| `jadx/android-lab` | jadx | `arsenal-android` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:jadx/android-decompile |
| `jsluice/linux-cli` | jsluice | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | adapter:jsluice/passive-discovery |
| `katana/network-lab` | katana | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | adapter:katana/passive-discovery<br>asset:katana/scoped-endpoint-crawl |
| `kics/linux-cli` | KICS | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:kics/iac-security-scan |
| `kubescape/kubernetes-lab` | Kubescape | `arsenal-kubernetes` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:kubescape/kubernetes-posture-and-runtime-scan |
| `mitmproxy/network-lab` | mitmproxy | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:mitmproxy/authorized-http-traffic-capture |
| `mobsf/container` | MobSF | `arsenal-android` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:mobsf/rest-static-analysis |
| `modelscan/linux-cli` | ModelScan | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:modelscan/serialized-model-safety-scan |
| `mythril/linux-cli` | Mythril, mythril | `arsenal-smart-contract` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset-lane:contract-static-analysis<br>asset:mythril/evm-symbolic-execution<br>tool:mythril/contract |
| `naabu/network-lab` | naabu | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:naabu/bounded-port-discovery |
| `njsscan/linux-cli` | njsscan | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | tool:njsscan/code |
| `nmap/network-lab` | nmap | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset-lane:service-identification<br>asset:nmap/bounded-service-fingerprinting |
| `npm/linux-cli` | npm | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:npm/npm-dependency-audit |
| `nuclei/network-lab` | nuclei | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:nuclei/signed-safe-template-validation |
| `objection/android-lab` | objection | `arsenal-android` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:objection/android-runtime-exploration<br>asset:objection/ios-runtime-exploration |
| `osv-scanner/linux-cli` | osv-scanner | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | adapter:osv-scanner/passive-discovery<br>asset:osv-scanner/dependency-vulnerability-analysis<br>tool:osv-scanner/deps |
| `otool/macos-cli` | otool | `arsenal-macos-ios` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:otool/ios-macos-load-command-analysis |
| `pefile/linux-cli` | pefile | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:pefile/pe-structure-analysis |
| `pip-audit/linux-cli` | pip-audit | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:pip-audit/python-dependency-vulnerability-analysis |
| `playwright/linux-cli` | Playwright | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:playwright/authenticated-browser-traffic-learning |
| `promptfoo/linux-cli` | promptfoo | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:promptfoo/ai-red-team-evaluation |
| `prowler/cloud-lab` | Prowler | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:prowler/aws-security-posture<br>asset:prowler/azure-security-posture |
| `psalm/linux-cli` | psalm | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | tool:psalm/code |
| `pyrit/linux-cli` | PyRIT | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:pyrit/generative-ai-risk-identification |
| `restler/network-lab` | RESTler | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:restler/stateful-openapi-sequence-testing |
| `retire-js/node-cli` | retire.js | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | tool:retire-js/deps |
| `rizin/linux-cli` | Rizin | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:rizin/binary-reverse-engineering |
| `roadrecon/cloud-lab` | ROADtools | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:roadtools/entra-identity-analysis |
| `rustscan/network-lab` | RustScan | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:rustscan/bounded-fast-port-prefilter |
| `schemathesis/network-lab` | Schemathesis | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:schemathesis/graphql-schema-guided-testing<br>asset:schemathesis/schema-guided-api-testing |
| `scorecard/linux-cli` | OpenSSF Scorecard | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:openssf-scorecard/repository-supply-chain-posture |
| `scoutsuite/cloud-cli` | ScoutSuite | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:scoutsuite/aws-attack-surface-audit<br>asset:scoutsuite/azure-attack-surface-audit |
| `semgrep/linux-cli` | semgrep | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | adapter:semgrep/passive-discovery<br>asset-lane:source-scanner-sweep<br>asset:semgrep/source-static-analysis<br>tool:semgrep/code |
| `skopeo/linux-cli` | skopeo | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:skopeo/container-registry-metadata |
| `slither/contract-cli` | slither | `arsenal-smart-contract` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset-lane:contract-static-analysis<br>asset:slither/solidity-vyper-static-analysis<br>tool:slither/contract |
| `spotbugs/linux-cli` | SpotBugs | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:spotbugs/java-bytecode-static-analysis |
| `ssh-audit/network-lab` | ssh-audit | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:ssh-audit/ssh-configuration-analysis |
| `subfinder/network-lab` | subfinder | `arsenal-network-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **UNAVAILABLE** | adapter:subfinder/passive-discovery<br>asset:subfinder/passive-subdomain-enumeration |
| `syft/linux-cli` | syft | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset-lane:dependency-extraction<br>asset:syft/artifact-sbom<br>asset:syft/container-image-sbom |
| `testssl-sh/linux-cli` | testssl.sh | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:testssl-sh/tls-configuration-analysis |
| `trivy/linux-cli` | trivy | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset-lane:source-scanner-sweep<br>asset:trivy/container-image-security-scan<br>asset:trivy/filesystem-security-scan<br>tool:trivy/deps<br>tool:trivy/secrets |
| `web-ext/linux-cli` | web-ext | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:web-ext/browser-extension-structure-lint |
| `websocat/network-lab` | websocat | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:websocat/websocket-protocol-observation |
| `yara/linux-cli` | YARA | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:yara/approved-rule-binary-scan |
| `zizmor/linux-cli` | zizmor | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:zizmor/github-actions-security-audit |
| `aegis/aegis-agent-permission-audit` | aegis-agent-permission-audit | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:aegis-agent-permission-audit/agent-tool-permission-analysis |
| `aegis/aegis-artifact-diff` | aegis-artifact-diff | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:aegis-artifact-diff/authorized-mobile-release-diff |
| `aegis/aegis-asar` | aegis-asar | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:bundle-unpack |
| `aegis/aegis-asset-classifier` | aegis-asset-classifier | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:aegis-asset-classifier/deterministic-asset-classification |
| `aegis/aegis-asset-triage` | aegis-asset-triage | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:asset-triage |
| `aegis/aegis-authz-matrix` | aegis-authz-matrix | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:authorization-matrix |
| `aegis/aegis-binary-triage` | aegis-binary-triage | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:binary-triage |
| `aegis/aegis-bola-probe` | aegis-bola-probe | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:object-reference-probe |
| `aegis/aegis-contract-patterns` | aegis-contract-patterns | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:contract-pattern-review |
| `aegis/aegis-firmware-arch` | aegis-firmware-arch | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:aegis-firmware-arch/firmware-architecture-detection |
| `aegis/aegis-github-org` | aegis-github-org | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:aegis-github-org/github-org-authorized-inventory<br>asset:aegis-github-org/github-org-public-inventory |
| `aegis/aegis-gitlab-group` | aegis-gitlab-group | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:aegis-gitlab-group/gitlab-group-authorized-inventory<br>asset:aegis-gitlab-group/gitlab-group-public-inventory |
| `aegis/aegis-llm-lab` | aegis-llm-lab | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:prompt-injection-suite<br>asset-lane:system-prompt-extraction<br>asset-lane:tool-abuse-chain |
| `aegis/aegis-memory-poisoning` | aegis-memory-poisoning | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:aegis-memory-poisoning/agent-memory-poisoning-regression |
| `aegis/aegis-model-provenance` | aegis-model-provenance | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:aegis-model-provenance/model-provenance-and-hash-ledger |
| `aegis/aegis-openapi-parser` | aegis-openapi-parser | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:mass-assignment<br>asset-lane:openapi-ingest |
| `aegis/aegis-output-oracle` | aegis-output-oracle | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:output-handling-review |
| `aegis/aegis-package-registry` | aegis-package-registry | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:aegis-package-registry/public-package-metadata |
| `aegis/aegis-policy-parser` | aegis-policy-parser | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:iam-policy-review |
| `aegis/aegis-rag-boundary` | aegis-rag-boundary | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **WAITING_FOR_PREREQUISITE** | asset:aegis-rag-boundary/rag-retrieval-trust-analysis |
| `aegis/aegis-store-metadata` | aegis-store-metadata | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset:aegis-store-metadata/public-listing-metadata |
| `aegis/aegis-strings` | aegis-strings | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:dependency-extraction<br>asset-lane:embedded-secret-scan |
| `aegis/crt.sh` | crt.sh | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:passive-certificate-transparency |
| `aegis/stdlib-http` | stdlib-http | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:metadata-endpoint-exposure<br>asset-lane:public-blob-review<br>asset-lane:public-bucket-review<br>asset-lane:rate-limit-check<br>asset-lane:security-headers<br>asset-lane:virtual-host-discovery |
| `aegis/stdlib-resolver` | stdlib-resolver | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:dns-enumeration<br>asset-lane:subdomain-takeover |
| `aegis/stdlib-ssl` | stdlib-ssl | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | asset-lane:tls-inspection |
