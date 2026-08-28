# Aegis backend inventory

Git SHA: `e4abae3302ff8277f5601f173ffa51fc3d99b3b0`

Canonical capabilities: **174**  
Logical backend claims: **146**  
Unique external backends: **74**  
Unique external executable runtimes: **74**  
Installed external backends: **40**

| Backend runtime | State | Runner | Version | Capabilities | Prerequisite |
|---|---|---|---|---:|---|
| `ghidra/headless` | UNAVAILABLE | `arsenal-binary` | `` | 1 |  |
| `angr/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-binary` | `angr 9.3.3` | 1 |  |
| `apktool/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-android` | `3.0.3` | 1 |  |
| `electron-asar/node-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `v3.4.1` | 1 |  |
| `azurehound/cloud-lab` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `` | 1 | local Entra fixture or explicitly supplied controlled tenant |
| `bandit/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `bandit 1.9.4` | 3 |  |
| `binwalk/firmware-lab` | WAITING_FOR_PREREQUISITE | `arsenal-firmware` | `Binwalk v2.3.3` | 1 |  |
| `brakeman/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `brakeman 7.1.1` | 2 |  |
| `capa/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-binary` | `capa 9.4.0` | 1 |  |
| `checkov/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `3.3.9` | 3 |  |
| `class-dump/macos-cli` | WAITING_FOR_PREREQUISITE | `arsenal-macos-ios` | `` | 1 | macOS worker; readiness: command -v class-dump && uname -s | grep Darwin |
| `cloudsplaining/cloud-lab` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `cloudsplaining, version 0.7.0` | 1 |  |
| `codeql/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | 1 |  |
| `detect-secrets/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `1.5.47` | 1 |  |
| `dnsx/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 1 |  |
| `echidna/contract-cli` | WAITING_FOR_PREREQUISITE | `arsenal-smart-contract` | `Echidna 2.3.3` | 1 |  |
| `firmadyne/qemu-lab` | WAITING_FOR_PREREQUISITE | `arsenal-firmware` | `` | 1 | opt-in privileged Linux worker with QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 |
| `firmae/qemu-lab` | WAITING_FOR_PREREQUISITE | `arsenal-firmware` | `` | 1 | opt-in privileged Linux worker with FirmAE/QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 && test -d /opt/FirmAE |
| `floss/linux-cli` | UNAVAILABLE | `arsenal-binary` | `` | 1 |  |
| `foundry/forge` | WAITING_FOR_PREREQUISITE | `arsenal-smart-contract` | `forge Version: 1.8.0` | 1 |  |
| `frida/device-cli` | WAITING_FOR_PREREQUISITE | `arsenal-android` | `` | 2 | operator-owned local emulator/device and fixture app; readiness: adb devices && frida-ps -U |
| `garak/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | 1 |  |
| `gau/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 1 |  |
| `gitleaks/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `gitleaks version 8.21.2` | 4 |  |
| `gosec/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `Version: dev` | 2 |  |
| `grpcurl/network-lab` | WAITING_FOR_PREREQUISITE | `arsenal-network-lab` | `grpcurl v1.9.3` | 1 |  |
| `grype/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `grype 0.116.1` | 3 |  |
| `http-probe/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 1 |  |
| `httpx/network-lab` | WAITING_FOR_PREREQUISITE | `arsenal-network-lab` | `__    __  __       _  __` | 1 |  |
| `jadx/android-lab` | UNAVAILABLE | `arsenal-android` | `` | 1 |  |
| `jsluice/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | 1 |  |
| `katana/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 2 |  |
| `kics/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `Keeping Infrastructure as Code Secure v2.1.20` | 1 |  |
| `kubescape/kubernetes-lab` | UNAVAILABLE | `arsenal-kubernetes` | `` | 1 |  |
| `mitmproxy/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 1 |  |
| `mobsf/container` | WAITING_FOR_PREREQUISITE | `arsenal-android` | `` | 1 | loopback MobSF service and synthetic APK; readiness: test -n "$AEGIS_MOBSF_URL" && curl -fsS "$AEGIS_MOBSF_URL/api/v1/scans" |
| `modelscan/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `modelscan, version 0.8.8` | 1 |  |
| `mythril/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-smart-contract` | `Mythril version v0.24.8` | 3 |  |
| `naabu/network-lab` | WAITING_FOR_PREREQUISITE | `arsenal-network-lab` | `__` | 1 |  |
| `njsscan/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `[34m` | 1 |  |
| `nmap/network-lab` | WAITING_FOR_PREREQUISITE | `arsenal-network-lab` | `Nmap version 7.93 ( https://nmap.org )` | 2 |  |
| `npm/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `9.2.0` | 1 |  |
| `nuclei/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 1 |  |
| `objection/android-lab` | WAITING_FOR_PREREQUISITE | `arsenal-android` | `` | 2 | Frida-capable operator-owned emulator/device; readiness: adb devices && frida-ps -U && objection --version |
| `osv-scanner/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `osv-scanner version: 2.5.1` | 3 |  |
| `otool/macos-cli` | WAITING_FOR_PREREQUISITE | `arsenal-macos-ios` | `` | 1 | macOS worker; readiness: command -v otool && uname -s | grep Darwin |
| `pefile/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-binary` | `pefile 2024.8.26` | 1 |  |
| `pip-audit/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | 1 |  |
| `playwright/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | 1 |  |
| `promptfoo/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | 1 |  |
| `prowler/cloud-lab` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `` | 2 | local cloud emulator or explicitly supplied controlled cloud account |
| `psalm/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `Psalm 6.16.1@f1f5de594dc76faf8784e02d3dc4716c91c6f6ac` | 1 |  |
| `pyrit/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | 1 |  |
| `restler/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 1 |  |
| `retire-js/node-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `5.4.3` | 1 |  |
| `rizin/linux-cli` | UNAVAILABLE | `arsenal-binary` | `` | 1 |  |
| `roadrecon/cloud-lab` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `` | 1 | local Entra fixture or explicitly supplied controlled tenant |
| `rustscan/network-lab` | WAITING_FOR_PREREQUISITE | `arsenal-network-lab` | `rustscan 2.4.1` | 1 |  |
| `schemathesis/network-lab` | WAITING_FOR_PREREQUISITE | `arsenal-network-lab` | `schemathesis, version 4.25.2` | 2 |  |
| `scorecard/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | 1 |  |
| `scoutsuite/cloud-cli` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `` | 2 | local cloud emulator or explicitly supplied controlled cloud account |
| `semgrep/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `1.172.0` | 4 |  |
| `skopeo/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `skopeo version 1.9.3` | 1 |  |
| `slither/contract-cli` | WAITING_FOR_PREREQUISITE | `arsenal-smart-contract` | `0.11.6` | 3 |  |
| `spotbugs/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `4.10.4` | 1 |  |
| `ssh-audit/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 1 |  |
| `subfinder/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | 2 |  |
| `syft/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `syft 1.51.1` | 3 |  |
| `testssl-sh/linux-cli` | UNAVAILABLE | `arsenal-network-lab` | `` | 1 |  |
| `trivy/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `Version: 0.73.0` | 5 |  |
| `web-ext/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `8.10.0` | 1 |  |
| `websocat/network-lab` | WAITING_FOR_PREREQUISITE | `arsenal-network-lab` | `websocat 1.14.1` | 1 |  |
| `yara/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-binary` | `4.2.3` | 1 |  |
| `zizmor/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `zizmor 1.29.0` | 1 |  |
| `aegis/aegis-agent-permission-audit` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-artifact-diff` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-asar` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-asset-classifier` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-asset-triage` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-authz-matrix` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-binary-triage` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-bola-probe` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-contract-patterns` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-firmware-arch` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-github-org` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 2 |  |
| `aegis/aegis-gitlab-group` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 2 |  |
| `aegis/aegis-llm-lab` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 3 |  |
| `aegis/aegis-memory-poisoning` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-model-provenance` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-openapi-parser` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 2 |  |
| `aegis/aegis-output-oracle` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-package-registry` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-policy-parser` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-rag-boundary` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-store-metadata` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/aegis-strings` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 2 |  |
| `aegis/crt.sh` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
| `aegis/stdlib-http` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 6 |  |
| `aegis/stdlib-resolver` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 2 |  |
| `aegis/stdlib-ssl` | WAITING_FOR_PREREQUISITE | `arsenal-core` | `aegis-internal` | 1 |  |
