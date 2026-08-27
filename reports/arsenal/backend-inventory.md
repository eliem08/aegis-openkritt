# Aegis backend inventory

Git SHA: ``

Canonical capabilities: **174**  
Unique external backends: **74**  
Installed external backends: **17**

| Backend | State | Version | Capabilities | Prerequisite |
|---|---|---|---:|---|
| `external:analyzeHeadless` | UNAVAILABLE | `` | 1 |  |
| `external:angr` | UNAVAILABLE | `` | 1 |  |
| `external:apktool` | UNAVAILABLE | `` | 1 |  |
| `external:asar` | UNAVAILABLE | `` | 1 |  |
| `external:azurehound` | WAITING_FOR_PREREQUISITE | `` | 1 | local Entra fixture or explicitly supplied controlled tenant |
| `external:bandit` | WAITING_FOR_PREREQUISITE | `bandit 1.9.4` | 3 |  |
| `external:binwalk` | UNAVAILABLE | `` | 1 |  |
| `external:brakeman` | WAITING_FOR_PREREQUISITE | `brakeman 7.1.1` | 2 |  |
| `external:capa` | UNAVAILABLE | `` | 1 |  |
| `external:checkov` | WAITING_FOR_PREREQUISITE | `3.3.9` | 3 |  |
| `external:class-dump` | WAITING_FOR_PREREQUISITE | `` | 1 | macOS worker; readiness: command -v class-dump && uname -s | grep Darwin |
| `external:cloudsplaining` | WAITING_FOR_PREREQUISITE | `cloudsplaining, version 0.7.0` | 1 |  |
| `external:codeql` | UNAVAILABLE | `` | 1 |  |
| `external:detect-secrets` | WAITING_FOR_PREREQUISITE | `1.5.47` | 1 |  |
| `external:dnsx` | UNAVAILABLE | `` | 1 |  |
| `external:echidna` | UNAVAILABLE | `` | 1 |  |
| `external:firmadyne` | WAITING_FOR_PREREQUISITE | `` | 1 | opt-in privileged Linux worker with QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 |
| `external:firmae` | WAITING_FOR_PREREQUISITE | `` | 1 | opt-in privileged Linux worker with FirmAE/QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 && test -d /opt/FirmAE |
| `external:floss` | UNAVAILABLE | `` | 1 |  |
| `external:forge` | UNAVAILABLE | `` | 1 |  |
| `external:frida` | WAITING_FOR_PREREQUISITE | `` | 2 | operator-owned local emulator/device and fixture app; readiness: adb devices && frida-ps -U |
| `external:garak` | UNAVAILABLE | `` | 1 |  |
| `external:gau` | UNAVAILABLE | `` | 1 |  |
| `external:gitleaks` | WAITING_FOR_PREREQUISITE | `gitleaks version 8.21.2` | 4 |  |
| `external:gosec` | WAITING_FOR_PREREQUISITE | `Version: dev` | 2 |  |
| `external:grpcurl` | UNAVAILABLE | `` | 1 |  |
| `external:grype` | WAITING_FOR_PREREQUISITE | `grype 0.116.1` | 3 |  |
| `external:http-probe` | UNAVAILABLE | `` | 1 |  |
| `external:httpx` | BACKEND_UNHEALTHY | `` | 1 |  |
| `external:jadx` | UNAVAILABLE | `` | 1 |  |
| `external:jsluice` | UNAVAILABLE | `` | 1 |  |
| `external:katana` | UNAVAILABLE | `` | 2 |  |
| `external:kics` | UNAVAILABLE | `` | 1 |  |
| `external:kubescape` | UNAVAILABLE | `` | 1 |  |
| `external:mitmproxy` | UNAVAILABLE | `` | 1 |  |
| `external:mobsf` | WAITING_FOR_PREREQUISITE | `` | 1 | loopback MobSF service and synthetic APK; readiness: test -n "$AEGIS_MOBSF_URL" && curl -fsS "$AEGIS_MOBSF_URL/api/v1/scans" |
| `external:modelscan` | UNAVAILABLE | `` | 1 |  |
| `external:myth` | WAITING_FOR_PREREQUISITE | `Mythril version v0.24.8` | 3 |  |
| `external:naabu` | UNAVAILABLE | `` | 1 |  |
| `external:njsscan` | WAITING_FOR_PREREQUISITE | `[34m` | 1 |  |
| `external:nmap` | UNAVAILABLE | `` | 2 |  |
| `external:npm` | WAITING_FOR_PREREQUISITE | `9.2.0` | 1 |  |
| `external:nuclei` | UNAVAILABLE | `` | 1 |  |
| `external:objection` | WAITING_FOR_PREREQUISITE | `` | 2 | Frida-capable operator-owned emulator/device; readiness: adb devices && frida-ps -U && objection --version |
| `external:osv-scanner` | WAITING_FOR_PREREQUISITE | `osv-scanner version: 2.5.1` | 3 |  |
| `external:otool` | WAITING_FOR_PREREQUISITE | `` | 1 | macOS worker; readiness: command -v otool && uname -s | grep Darwin |
| `external:pefile` | UNAVAILABLE | `` | 1 |  |
| `external:pip-audit` | UNAVAILABLE | `` | 1 |  |
| `external:playwright` | UNAVAILABLE | `` | 1 |  |
| `external:promptfoo` | UNAVAILABLE | `` | 1 |  |
| `external:prowler` | WAITING_FOR_PREREQUISITE | `` | 2 | local cloud emulator or explicitly supplied controlled cloud account |
| `external:psalm` | WAITING_FOR_PREREQUISITE | `Psalm 6.16.1@f1f5de594dc76faf8784e02d3dc4716c91c6f6ac` | 1 |  |
| `external:pyrit` | UNAVAILABLE | `` | 1 |  |
| `external:restler` | UNAVAILABLE | `` | 1 |  |
| `external:retire` | WAITING_FOR_PREREQUISITE | `5.4.3` | 1 |  |
| `external:rizin` | UNAVAILABLE | `` | 1 |  |
| `external:roadrecon` | WAITING_FOR_PREREQUISITE | `` | 1 | local Entra fixture or explicitly supplied controlled tenant |
| `external:rustscan` | UNAVAILABLE | `` | 1 |  |
| `external:schemathesis` | UNAVAILABLE | `` | 2 |  |
| `external:scorecard` | UNAVAILABLE | `` | 1 |  |
| `external:scout` | WAITING_FOR_PREREQUISITE | `` | 2 | local cloud emulator or explicitly supplied controlled cloud account |
| `external:semgrep` | WAITING_FOR_PREREQUISITE | `1.172.0` | 4 |  |
| `external:skopeo` | UNAVAILABLE | `` | 1 |  |
| `external:slither` | WAITING_FOR_PREREQUISITE | `0.11.6` | 3 |  |
| `external:spotbugs` | UNAVAILABLE | `` | 1 |  |
| `external:ssh-audit` | UNAVAILABLE | `` | 1 |  |
| `external:subfinder` | UNAVAILABLE | `` | 2 |  |
| `external:syft` | UNAVAILABLE | `` | 3 |  |
| `external:testssl.sh` | UNAVAILABLE | `` | 1 |  |
| `external:trivy` | WAITING_FOR_PREREQUISITE | `Version: 0.73.0` | 5 |  |
| `external:web-ext` | UNAVAILABLE | `` | 1 |  |
| `external:websocat` | UNAVAILABLE | `` | 1 |  |
| `external:yara` | UNAVAILABLE | `` | 1 |  |
| `external:zizmor` | UNAVAILABLE | `` | 1 |  |
| `internal:aegis-agent-permission-audit` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-artifact-diff` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-asar` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-asset-classifier` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-asset-triage` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-authz-matrix` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-binary-triage` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-bola-probe` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-contract-patterns` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-firmware-arch` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-github-org` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 2 |  |
| `internal:aegis-gitlab-group` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 2 |  |
| `internal:aegis-llm-lab` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 3 |  |
| `internal:aegis-memory-poisoning` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-model-provenance` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-openapi-parser` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 2 |  |
| `internal:aegis-output-oracle` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-package-registry` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-policy-parser` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-rag-boundary` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-store-metadata` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:aegis-strings` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 2 |  |
| `internal:crt.sh` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
| `internal:stdlib-http` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 6 |  |
| `internal:stdlib-resolver` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 2 |  |
| `internal:stdlib-ssl` | WAITING_FOR_PREREQUISITE | `aegis-internal` | 1 |  |
