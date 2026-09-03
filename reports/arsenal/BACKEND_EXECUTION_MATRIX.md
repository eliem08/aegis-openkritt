# Backend Execution Matrix

Git SHA: `61c0d100020008e6653ea66a9867a5440a6fbfca`
Arsenal image: ``

| Backend runtime | Tool | Runner | Version | Installed | Healthy | State | Capabilities |
|---|---|---|---|---|---|---|---|
| `ghidra/headless` | Ghidra | `arsenal-binary` | `Ghidra 12.1.3` | True | True | **EXECUTED_PASS** | asset:ghidra/headless-binary-analysis |
| `angr/linux-cli` | angr | `arsenal-binary` | `angr 9.3.3` | True | True | **EXECUTED_PASS** | asset:angr/binary-control-flow-analysis |
| `apktool/linux-cli` | apktool | `arsenal-android` | `3.0.3` | True | True | **EXECUTED_PASS** | asset:apktool/android-resource-and-manifest-decode |
| `electron-asar/node-cli` | @electron/asar | `arsenal-linux` | `v3.4.1` | True | True | **EXECUTED_PASS** | asset:electron-asar/electron-package-extraction |
| `azurehound/cloud-lab` | AzureHound | `arsenal-cloud-lab` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:azurehound/azure-entra-relationship-collection |
| `bandit/linux-cli` | Bandit, bandit | `arsenal-linux` | `bandit 1.9.4` | True | True | **EXECUTED_PASS** | asset-lane:source-scanner-sweep<br>asset:bandit/python-security-static-analysis<br>tool:bandit/code |
| `binwalk/firmware-lab` | binwalk | `arsenal-firmware` | `Binwalk v2.3.3` | True | True | **EXECUTED_PASS** | asset:binwalk/firmware-structure-analysis |
| `brakeman/linux-cli` | Brakeman, brakeman | `arsenal-linux` | `brakeman 7.1.1` | True | True | **EXECUTED_PASS** | asset:brakeman/rails-security-static-analysis<br>tool:brakeman/code |
| `capa/linux-cli` | capa | `arsenal-binary` | `capa 9.4.0` | True | True | **EXECUTED_PASS** | asset:capa/binary-capability-analysis |
| `checkov/linux-cli` | Checkov, checkov | `arsenal-linux` | `3.3.9` | True | True | **EXECUTED_PASS** | asset:checkov/container-image-policy-scan<br>asset:checkov/iac-cicd-and-container-policy-scan<br>tool:checkov/deps |
| `class-dump/macos-cli` | class-dump | `arsenal-macos-ios` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:class-dump/objective-c-interface-recovery |
| `cloudsplaining/cloud-lab` | Cloudsplaining | `arsenal-cloud-lab` | `cloudsplaining, version 0.7.0` | True | True | **EXECUTED_PASS** | asset:cloudsplaining/aws-iam-risk-analysis |
| `codeql/linux-cli` | CodeQL | `arsenal-linux` | `CodeQL command-line toolchain release 2.26.4.` | True | True | **EXECUTED_PASS** | asset:codeql/cross-file-dataflow |
| `detect-secrets/linux-cli` | detect-secrets | `arsenal-linux` | `1.5.47` | True | True | **EXECUTED_PASS** | tool:detect-secrets/secrets |
| `dnsx/network-lab` | dnsx | `arsenal-network-lab` | `_             __  __` | True | True | **EXECUTED_PASS** | asset:dnsx/dns-resolution-and-wildcard-filtering |
| `echidna/contract-cli` | Echidna | `arsenal-smart-contract` | `Echidna 2.3.3` | True | True | **EXECUTED_PASS** | asset:echidna/smart-contract-property-fuzzing |
| `firmadyne/qemu-lab` | Firmadyne | `arsenal-firmware` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:firmadyne/firmware-emulation-fallback |
| `firmae/qemu-lab` | FirmAE | `arsenal-firmware` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:firmae/firmware-emulation |
| `floss/linux-cli` | FLOSS | `arsenal-binary` | `floss v3.1.1-0-g3cd3ee6` | True | True | **EXECUTED_PASS** | asset:floss/static-string-deobfuscation |
| `foundry/forge` | Foundry | `arsenal-smart-contract` | `forge Version: 1.8.0` | True | True | **EXECUTED_PASS** | asset:foundry/smart-contract-fuzz-and-invariant-tests |
| `frida/device-cli` | Frida | `arsenal-android` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:frida/android-runtime-instrumentation<br>asset:frida/ios-runtime-instrumentation |
| `garak/linux-cli` | garak | `arsenal-linux` | `garak LLM vulnerability scanner v0.16.0 ( https://github.com/NVIDIA/garak ) at 2026-09-03T14:17:15.264182` | True | True | **EXECUTED_PASS** | asset:garak/llm-security-probing |
| `gau/network-lab` | gau | `arsenal-network-lab` | `` | False | False | **UNAVAILABLE** | adapter:gau/passive-discovery |
| `gitleaks/linux-cli` | gitleaks | `arsenal-linux` | `gitleaks version 8.21.2` | True | True | **EXECUTED_PASS** | adapter:gitleaks/passive-discovery<br>asset-lane:source-scanner-sweep<br>asset:gitleaks/git-secret-detection<br>tool:gitleaks/secrets |
| `gosec/linux-cli` | gosec | `arsenal-linux` | `Version: dev` | True | True | **EXECUTED_PASS** | asset:gosec/go-security-static-analysis<br>tool:gosec/code |
| `grpcurl/network-lab` | grpcurl | `arsenal-network-lab` | `grpcurl v1.9.3` | True | True | **EXECUTED_PASS** | asset:grpcurl/grpc-service-introspection |
| `grype/linux-cli` | grype | `arsenal-linux` | `grype 0.116.1` | True | True | **EXECUTED_PASS** | asset:grype/artifact-vulnerability-scan<br>asset:grype/container-image-vulnerability-scan<br>tool:grype/deps |
| `httpx/network-lab` | http-probe, httpx | `arsenal-network-lab` | `__    __  __       _  __` | True | True | **EXECUTED_PASS** | adapter:http-probe/passive-discovery<br>asset:httpx/http-service-enrichment |
| `jadx/android-lab` | jadx | `arsenal-android` | `1.5.6` | True | True | **EXECUTED_PASS** | asset:jadx/android-decompile |
| `jsluice/linux-cli` | jsluice | `arsenal-linux` | `jsluice - Extract URLs, paths, and secrets from JavaScript files` | True | True | **EXECUTED_PASS** | adapter:jsluice/passive-discovery |
| `katana/network-lab` | katana | `arsenal-network-lab` | `__        __                ` | True | True | **EXECUTED_PASS** | adapter:katana/passive-discovery<br>asset:katana/scoped-endpoint-crawl |
| `kics/linux-cli` | KICS | `arsenal-linux` | `Keeping Infrastructure as Code Secure v2.1.20` | True | True | **EXECUTED_PASS** | asset:kics/iac-security-scan |
| `kubescape/kubernetes-lab` | Kubescape | `arsenal-kubernetes` | `Your current version is: v4.0.12` | True | True | **EXECUTED_PASS** | asset:kubescape/kubernetes-posture-and-runtime-scan |
| `mitmproxy/network-lab` | mitmproxy | `arsenal-network-lab` | `Mitmproxy: 12.2.3` | True | True | **EXECUTED_PASS** | asset:mitmproxy/authorized-http-traffic-capture |
| `mobsf/container` | MobSF | `arsenal-android` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:mobsf/rest-static-analysis |
| `modelscan/linux-cli` | ModelScan | `arsenal-linux` | `modelscan, version 0.8.8` | True | True | **EXECUTED_PASS** | asset:modelscan/serialized-model-safety-scan |
| `mythril/linux-cli` | Mythril, mythril | `arsenal-smart-contract` | `Mythril version v0.24.8` | True | True | **EXECUTED_PASS** | asset-lane:contract-static-analysis<br>asset:mythril/evm-symbolic-execution<br>tool:mythril/contract |
| `naabu/network-lab` | naabu | `arsenal-network-lab` | `__` | True | True | **EXECUTED_PASS** | asset:naabu/bounded-port-discovery |
| `njsscan/linux-cli` | njsscan | `arsenal-linux` | `[34m` | True | True | **EXECUTED_PASS** | tool:njsscan/code |
| `nmap/network-lab` | nmap | `arsenal-network-lab` | `Nmap version 7.93 ( https://nmap.org )` | True | True | **EXECUTED_PASS** | asset-lane:service-identification<br>asset:nmap/bounded-service-fingerprinting |
| `npm/linux-cli` | npm | `arsenal-linux` | `10.9.4` | True | True | **EXECUTED_PASS** | asset:npm/npm-dependency-audit |
| `nuclei/network-lab` | nuclei | `arsenal-network-lab` | `[[34mINF[0m] Nuclei Engine Version: v3.3.0[[34mINF[0m] Nuclei Config Directory: /root/.config/nuclei[[34mINF[0m] Nuclei Cache Directory: /root/.cache/nuclei[[34mINF[0m] PDCP Directory: /root/.pdcp` | True | True | **EXECUTED_PASS** | asset:nuclei/signed-safe-template-validation |
| `objection/android-lab` | objection | `arsenal-android` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:objection/android-runtime-exploration<br>asset:objection/ios-runtime-exploration |
| `osv-scanner/linux-cli` | osv-scanner | `arsenal-linux` | `osv-scanner version: 2.5.1` | True | True | **EXECUTED_PASS** | adapter:osv-scanner/passive-discovery<br>asset:osv-scanner/dependency-vulnerability-analysis<br>tool:osv-scanner/deps |
| `otool/macos-cli` | otool | `arsenal-macos-ios` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:otool/ios-macos-load-command-analysis |
| `pefile/linux-cli` | pefile | `arsenal-binary` | `pefile 2024.8.26` | True | True | **EXECUTED_PASS** | asset:pefile/pe-structure-analysis |
| `pip-audit/linux-cli` | pip-audit | `arsenal-linux` | `pip-audit 2.10.1` | True | True | **EXECUTED_PASS** | asset:pip-audit/python-dependency-vulnerability-analysis |
| `playwright/linux-cli` | Playwright | `arsenal-linux` | `Version 1.60.0` | True | True | **EXECUTED_PASS** | asset:playwright/authenticated-browser-traffic-learning |
| `promptfoo/linux-cli` | promptfoo | `arsenal-linux` | `0.122.2` | True | True | **EXECUTED_PASS** | asset:promptfoo/ai-red-team-evaluation |
| `prowler/cloud-lab` | Prowler | `arsenal-cloud-lab` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:prowler/aws-security-posture<br>asset:prowler/azure-security-posture |
| `psalm/linux-cli` | psalm | `arsenal-linux` | `Psalm 6.16.1@f1f5de594dc76faf8784e02d3dc4716c91c6f6ac` | True | True | **EXECUTED_PASS** | tool:psalm/code |
| `pyrit/linux-cli` | PyRIT | `arsenal-linux` | `1.0.1` | True | True | **EXECUTED_PASS** | asset:pyrit/generative-ai-risk-identification |
| `restler/network-lab` | RESTler | `arsenal-network-lab` | `RESTler 9.3.1` | True | True | **EXECUTED_PASS** | asset:restler/stateful-openapi-sequence-testing |
| `retire-js/node-cli` | retire.js | `arsenal-linux` | `5.4.3` | True | True | **EXECUTED_PASS** | tool:retire-js/deps |
| `rizin/linux-cli` | Rizin | `arsenal-binary` | `-- Assemble opcodes with the 'a' and 'A' keys in visual mode, which are bindings to the 'wa' and 'wA' commands` | True | True | **EXECUTED_PASS** | asset:rizin/binary-reverse-engineering |
| `roadrecon/cloud-lab` | ROADtools | `arsenal-cloud-lab` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:roadtools/entra-identity-analysis |
| `rustscan/network-lab` | RustScan | `arsenal-network-lab` | `rustscan 2.4.1` | True | True | **EXECUTED_PASS** | asset:rustscan/bounded-fast-port-prefilter |
| `schemathesis/network-lab` | Schemathesis | `arsenal-network-lab` | `schemathesis, version 4.25.2` | True | True | **EXECUTED_PASS** | asset:schemathesis/graphql-schema-guided-testing<br>asset:schemathesis/schema-guided-api-testing |
| `scorecard/linux-cli` | OpenSSF Scorecard | `arsenal-linux` | `OpenSSF Scorecard v5.5.0` | True | True | **EXECUTED_PASS** | asset:openssf-scorecard/repository-supply-chain-posture |
| `scoutsuite/cloud-cli` | ScoutSuite | `arsenal-cloud-lab` | `` | False | False | **WAITING_FOR_PREREQUISITE** | asset:scoutsuite/aws-attack-surface-audit<br>asset:scoutsuite/azure-attack-surface-audit |
| `semgrep/linux-cli` | semgrep | `arsenal-linux` | `1.172.0` | True | True | **EXECUTED_PASS** | adapter:semgrep/passive-discovery<br>asset-lane:source-scanner-sweep<br>asset:semgrep/source-static-analysis<br>tool:semgrep/code |
| `skopeo/linux-cli` | skopeo | `arsenal-linux` | `skopeo version 1.9.3` | True | True | **EXECUTED_PASS** | asset:skopeo/container-registry-metadata |
| `slither/contract-cli` | slither | `arsenal-smart-contract` | `0.11.6` | True | True | **EXECUTED_PASS** | asset-lane:contract-static-analysis<br>asset:slither/solidity-vyper-static-analysis<br>tool:slither/contract |
| `spotbugs/linux-cli` | SpotBugs | `arsenal-linux` | `4.10.4` | True | True | **EXECUTED_PASS** | asset:spotbugs/java-bytecode-static-analysis |
| `ssh-audit/network-lab` | ssh-audit | `arsenal-network-lab` | `usage: ssh-audit [-h] [-4] [-6] [-b] [-c] [-d]` | True | True | **EXECUTED_PASS** | asset:ssh-audit/ssh-configuration-analysis |
| `subfinder/network-lab` | subfinder | `arsenal-network-lab` | `` | False | False | **UNAVAILABLE** | adapter:subfinder/passive-discovery<br>asset:subfinder/passive-subdomain-enumeration |
| `syft/linux-cli` | syft | `arsenal-linux` | `syft 1.51.1` | True | True | **EXECUTED_PASS** | asset-lane:dependency-extraction<br>asset:syft/artifact-sbom<br>asset:syft/container-image-sbom |
| `testssl-sh/linux-cli` | testssl.sh | `arsenal-network-lab` | `[1m` | True | True | **EXECUTED_PASS** | asset:testssl-sh/tls-configuration-analysis |
| `trivy/linux-cli` | trivy | `arsenal-linux` | `Version: 0.73.0` | True | True | **EXECUTED_PASS** | asset-lane:source-scanner-sweep<br>asset:trivy/container-image-security-scan<br>asset:trivy/filesystem-security-scan<br>tool:trivy/deps<br>tool:trivy/secrets |
| `web-ext/linux-cli` | web-ext | `arsenal-linux` | `8.10.0` | True | True | **EXECUTED_PASS** | asset:web-ext/browser-extension-structure-lint |
| `websocat/network-lab` | websocat | `arsenal-network-lab` | `websocat 1.14.1` | True | True | **EXECUTED_PASS** | asset:websocat/websocket-protocol-observation |
| `yara/linux-cli` | YARA | `arsenal-binary` | `4.2.3` | True | True | **EXECUTED_PASS** | asset:yara/approved-rule-binary-scan |
| `zizmor/linux-cli` | zizmor | `arsenal-linux` | `zizmor 1.29.0` | True | True | **EXECUTED_PASS** | asset:zizmor/github-actions-security-audit |
| `aegis/aegis-agent-permission-audit` | aegis-agent-permission-audit | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-agent-permission-audit/agent-tool-permission-analysis |
| `aegis/aegis-artifact-diff` | aegis-artifact-diff | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-artifact-diff/authorized-mobile-release-diff |
| `aegis/aegis-asar` | aegis-asar | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:bundle-unpack |
| `aegis/aegis-asset-classifier` | aegis-asset-classifier | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-asset-classifier/deterministic-asset-classification |
| `aegis/aegis-asset-triage` | aegis-asset-triage | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:asset-triage |
| `aegis/aegis-authz-matrix` | aegis-authz-matrix | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:authorization-matrix |
| `aegis/aegis-binary-triage` | aegis-binary-triage | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:binary-triage |
| `aegis/aegis-bola-probe` | aegis-bola-probe | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:object-reference-probe |
| `aegis/aegis-contract-patterns` | aegis-contract-patterns | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:contract-pattern-review |
| `aegis/aegis-firmware-arch` | aegis-firmware-arch | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-firmware-arch/firmware-architecture-detection |
| `aegis/aegis-github-org` | aegis-github-org | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-github-org/github-org-authorized-inventory<br>asset:aegis-github-org/github-org-public-inventory |
| `aegis/aegis-gitlab-group` | aegis-gitlab-group | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-gitlab-group/gitlab-group-authorized-inventory<br>asset:aegis-gitlab-group/gitlab-group-public-inventory |
| `aegis/aegis-llm-lab` | aegis-llm-lab | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:prompt-injection-suite<br>asset-lane:system-prompt-extraction<br>asset-lane:tool-abuse-chain |
| `aegis/aegis-memory-poisoning` | aegis-memory-poisoning | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-memory-poisoning/agent-memory-poisoning-regression |
| `aegis/aegis-model-provenance` | aegis-model-provenance | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-model-provenance/model-provenance-and-hash-ledger |
| `aegis/aegis-openapi-parser` | aegis-openapi-parser | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:mass-assignment<br>asset-lane:openapi-ingest |
| `aegis/aegis-output-oracle` | aegis-output-oracle | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:output-handling-review |
| `aegis/aegis-package-registry` | aegis-package-registry | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-package-registry/public-package-metadata |
| `aegis/aegis-policy-parser` | aegis-policy-parser | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:iam-policy-review |
| `aegis/aegis-rag-boundary` | aegis-rag-boundary | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-rag-boundary/rag-retrieval-trust-analysis |
| `aegis/aegis-store-metadata` | aegis-store-metadata | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset:aegis-store-metadata/public-listing-metadata |
| `aegis/aegis-strings` | aegis-strings | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:dependency-extraction<br>asset-lane:embedded-secret-scan |
| `aegis/crt.sh` | crt.sh | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:passive-certificate-transparency |
| `aegis/stdlib-http` | stdlib-http | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:metadata-endpoint-exposure<br>asset-lane:public-blob-review<br>asset-lane:public-bucket-review<br>asset-lane:rate-limit-check<br>asset-lane:security-headers<br>asset-lane:virtual-host-discovery |
| `aegis/stdlib-resolver` | stdlib-resolver | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:dns-enumeration<br>asset-lane:subdomain-takeover |
| `aegis/stdlib-ssl` | stdlib-ssl | `arsenal-core` | `aegis-internal` | True | True | **WAITING_FOR_PREREQUISITE** | asset-lane:tls-inspection |
