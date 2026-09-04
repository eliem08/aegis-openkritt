# Backend Execution Matrix

Git SHA: `976a80b94d0c184b0ebb3493847305da708efafc`
Source Git SHA: `976a80b94d0c184b0ebb3493847305da708efafc`
Generated At: `2026-09-04T02:47:04.652331+00:00`
Verdict: **ACTIVE_LOCAL_SOFTWARE_SUBSET_VERIFIED_EXTERNAL_PREREQUISITES_REMAIN**

| Backend runtime | Tool | Runner | Active/Migrated | Kind | Proof Kind | Positive | Negative | Global State | Local Readiness |
|---|---|---|---|---|---|---|---|---|---|
| `ghidra/headless` | Ghidra | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `angr/linux-cli` | angr | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `apktool/linux-cli` | apktool | `arsenal-android` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `electron-asar/node-cli` | @electron/asar | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `azurehound/cloud-lab` | AzureHound | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `bandit/linux-cli` | Bandit, bandit | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `binwalk/firmware-lab` | binwalk | `arsenal-firmware` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `brakeman/linux-cli` | Brakeman, brakeman | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `capa/linux-cli` | capa | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `checkov/linux-cli` | Checkov, checkov | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `class-dump/macos-cli` | class-dump | `arsenal-macos-ios` | migrated | EXTERNAL_TOOL | `MIGRATED_EQUIVALENT` | MIGRATED | MIGRATED | **MIGRATED** | `WAITING_FOR_PREREQUISITE` |
| `cloudsplaining/cloud-lab` | Cloudsplaining | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `codeql/linux-cli` | CodeQL | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `detect-secrets/linux-cli` | detect-secrets | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `dnsx/network-lab` | dnsx | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `echidna/contract-cli` | Echidna | `arsenal-smart-contract` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `firmadyne/qemu-lab` | Firmadyne | `arsenal-firmware` | migrated | EXTERNAL_TOOL | `MIGRATED_EQUIVALENT` | MIGRATED | MIGRATED | **MIGRATED** | `WAITING_FOR_PREREQUISITE` |
| `firmae/qemu-lab` | FirmAE | `arsenal-firmware` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `floss/linux-cli` | FLOSS | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `foundry/forge` | Foundry | `arsenal-smart-contract` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `frida/device-cli` | Frida | `arsenal-android` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `garak/linux-cli` | garak | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `gau/network-lab` | gau | `arsenal-network-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `UNAVAILABLE` |
| `gitleaks/linux-cli` | gitleaks | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `gosec/linux-cli` | gosec | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `grpcurl/network-lab` | grpcurl | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `grype/linux-cli` | grype | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `httpx/network-lab` | http-probe, httpx | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `jadx/android-lab` | jadx | `arsenal-android` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `jsluice/linux-cli` | jsluice | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `katana/network-lab` | katana | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `kics/linux-cli` | KICS | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `kubescape/kubernetes-lab` | Kubescape | `arsenal-kubernetes` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `mitmproxy/network-lab` | mitmproxy | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `mobsf/container` | MobSF | `arsenal-android` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `modelscan/linux-cli` | ModelScan | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `mythril/linux-cli` | Mythril, mythril | `arsenal-smart-contract` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `naabu/network-lab` | naabu | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `njsscan/linux-cli` | njsscan | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `nmap/network-lab` | nmap | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `npm/linux-cli` | npm | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `nuclei/network-lab` | nuclei | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `objection/android-lab` | objection | `arsenal-android` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `osv-scanner/linux-cli` | osv-scanner | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `otool/macos-cli` | otool | `arsenal-macos-ios` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `pefile/linux-cli` | pefile | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `pip-audit/linux-cli` | pip-audit | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `playwright/linux-cli` | Playwright | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `promptfoo/linux-cli` | promptfoo | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `prowler/cloud-lab` | Prowler | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `psalm/linux-cli` | psalm | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `pyrit/linux-cli` | PyRIT | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `restler/network-lab` | RESTler | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `retire-js/node-cli` | retire.js | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `rizin/linux-cli` | Rizin | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `roadrecon/cloud-lab` | ROADtools | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `rustscan/network-lab` | RustScan | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `schemathesis/network-lab` | Schemathesis | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `scorecard/linux-cli` | OpenSSF Scorecard | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `scoutsuite/cloud-cli` | ScoutSuite | `arsenal-cloud-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `semgrep/linux-cli` | semgrep | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `skopeo/linux-cli` | skopeo | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `slither/contract-cli` | slither | `arsenal-smart-contract` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `spotbugs/linux-cli` | SpotBugs | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `ssh-audit/network-lab` | ssh-audit | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `subfinder/network-lab` | subfinder | `arsenal-network-lab` | active | EXTERNAL_TOOL | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `UNAVAILABLE` |
| `syft/linux-cli` | syft | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `testssl-sh/linux-cli` | testssl.sh | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `trivy/linux-cli` | trivy | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `web-ext/linux-cli` | web-ext | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `websocat/network-lab` | websocat | `arsenal-network-lab` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `yara/linux-cli` | YARA | `arsenal-binary` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `zizmor/linux-cli` | zizmor | `arsenal-linux` | active | EXTERNAL_TOOL | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-agent-permission-audit` | aegis-agent-permission-audit | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-artifact-diff` | aegis-artifact-diff | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-asar` | aegis-asar | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-asset-classifier` | aegis-asset-classifier | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-asset-triage` | aegis-asset-triage | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-authz-matrix` | aegis-authz-matrix | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-binary-triage` | aegis-binary-triage | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-bola-probe` | aegis-bola-probe | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-contract-patterns` | aegis-contract-patterns | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-firmware-arch` | aegis-firmware-arch | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-github-org` | aegis-github-org | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-gitlab-group` | aegis-gitlab-group | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-llm-lab` | aegis-llm-lab | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-memory-poisoning` | aegis-memory-poisoning | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-model-provenance` | aegis-model-provenance | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-openapi-parser` | aegis-openapi-parser | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-output-oracle` | aegis-output-oracle | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-package-registry` | aegis-package-registry | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-policy-parser` | aegis-policy-parser | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-rag-boundary` | aegis-rag-boundary | `arsenal-core` | active | INTERNAL_AEGIS | `REAL_BACKEND` | PASS | PASS | **EXECUTED_PASS** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-store-metadata` | aegis-store-metadata | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/aegis-strings` | aegis-strings | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/crt.sh` | crt.sh | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/stdlib-http` | stdlib-http | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/stdlib-resolver` | stdlib-resolver | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
| `aegis/stdlib-ssl` | stdlib-ssl | `arsenal-core` | active | INTERNAL_AEGIS | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | **WAITING_FOR_PREREQUISITE** | `WAITING_FOR_PREREQUISITE` |
