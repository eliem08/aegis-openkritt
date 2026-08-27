# Never-executed arsenal backends

Backlog: **59**

| Runtime | State | Runner | Version | Failure | Remediation |
|---|---|---|---|---|---|
| `angr/linux-cli` | UNAVAILABLE | `arsenal-binary` | `` | binary not found | install and pin runtime; connect native-output parser |
| `apktool/linux-cli` | UNAVAILABLE | `arsenal-android` | `` | binary not found | install and pin runtime; connect native-output parser |
| `azurehound/cloud-lab` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser; provision arsenal-cloud-lab: local Entra fixture or explicitly supplied controlled tenant |
| `binwalk/firmware-lab` | UNAVAILABLE | `arsenal-firmware` | `` | binary not found | install and pin runtime; connect native-output parser |
| `capa/linux-cli` | UNAVAILABLE | `arsenal-binary` | `` | binary not found | install and pin runtime; connect native-output parser |
| `class-dump/macos-cli` | WAITING_FOR_PREREQUISITE | `arsenal-macos-ios` | `` | macOS worker; readiness: command -v class-dump && uname -s | grep Darwin | install and pin runtime; connect native-output parser; provision arsenal-macos-ios: macOS worker; readiness: command -v class-dump && uname -s | grep Darwin |
| `cloudsplaining/cloud-lab` | UNAVAILABLE | `arsenal-cloud-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `codeql/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
| `dnsx/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `echidna/contract-cli` | UNAVAILABLE | `arsenal-smart-contract` | `` | binary not found | install and pin runtime; connect native-output parser |
| `electron-asar/node-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
| `firmadyne/qemu-lab` | WAITING_FOR_PREREQUISITE | `arsenal-firmware` | `` | opt-in privileged Linux worker with QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 | install and pin runtime; connect native-output parser; provision arsenal-firmware: opt-in privileged Linux worker with QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 |
| `firmae/qemu-lab` | WAITING_FOR_PREREQUISITE | `arsenal-firmware` | `` | opt-in privileged Linux worker with FirmAE/QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 && test -d /opt/FirmAE | install and pin runtime; connect native-output parser; provision arsenal-firmware: opt-in privileged Linux worker with FirmAE/QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 && test -d /opt/FirmAE |
| `floss/linux-cli` | UNAVAILABLE | `arsenal-binary` | `` | binary not found | install and pin runtime; connect native-output parser |
| `foundry/forge` | UNAVAILABLE | `arsenal-smart-contract` | `` | binary not found | install and pin runtime; connect native-output parser |
| `frida/device-cli` | WAITING_FOR_PREREQUISITE | `arsenal-android` | `` | operator-owned local emulator/device and fixture app; readiness: adb devices && frida-ps -U | install and pin runtime; connect native-output parser; provision arsenal-android: operator-owned local emulator/device and fixture app; readiness: adb devices && frida-ps -U |
| `garak/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `gau/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `ghidra/headless` | UNAVAILABLE | `arsenal-binary` | `` | binary not found | install and pin runtime; connect native-output parser |
| `grpcurl/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `http-probe/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `httpx/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `jadx/android-lab` | UNAVAILABLE | `arsenal-android` | `` | binary not found | install and pin runtime; connect native-output parser |
| `jsluice/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `katana/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `kics/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
| `kubescape/kubernetes-lab` | UNAVAILABLE | `arsenal-kubernetes` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `mitmproxy/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `mobsf/container` | WAITING_FOR_PREREQUISITE | `arsenal-android` | `` | loopback MobSF service and synthetic APK; readiness: test -n "$AEGIS_MOBSF_URL" && curl -fsS "$AEGIS_MOBSF_URL/api/v1/scans" | install and pin runtime; connect native-output parser; provision arsenal-android: loopback MobSF service and synthetic APK; readiness: test -n "$AEGIS_MOBSF_URL" && curl -fsS "$AEGIS_MOBSF_URL/api/v1/scans" |
| `modelscan/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
| `naabu/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `nmap/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `npm/linux-cli` | WAITING_FOR_PREREQUISITE | `arsenal-linux` | `10.9.8` | backend is present but its deterministic positive/negative fixture provider is not connected to the canonical executor | connect native-output parser |
| `nuclei/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `objection/android-lab` | WAITING_FOR_PREREQUISITE | `arsenal-android` | `` | Frida-capable operator-owned emulator/device; readiness: adb devices && frida-ps -U && objection --version | install and pin runtime; connect native-output parser; provision arsenal-android: Frida-capable operator-owned emulator/device; readiness: adb devices && frida-ps -U && objection --version |
| `otool/macos-cli` | WAITING_FOR_PREREQUISITE | `arsenal-macos-ios` | `` | macOS worker; readiness: command -v otool && uname -s | grep Darwin | install and pin runtime; connect native-output parser; provision arsenal-macos-ios: macOS worker; readiness: command -v otool && uname -s | grep Darwin |
| `pefile/linux-cli` | UNAVAILABLE | `arsenal-binary` | `` | binary not found | install and pin runtime; connect native-output parser |
| `pip-audit/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
| `playwright/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `promptfoo/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `prowler/cloud-lab` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser; provision arsenal-cloud-lab: local cloud emulator or explicitly supplied controlled cloud account |
| `pyrit/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `restler/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; connect native-output parser |
| `rizin/linux-cli` | UNAVAILABLE | `arsenal-binary` | `` | binary not found | install and pin runtime; connect native-output parser |
| `roadrecon/cloud-lab` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser; provision arsenal-cloud-lab: local Entra fixture or explicitly supplied controlled tenant |
| `rustscan/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `schemathesis/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `scorecard/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `scoutsuite/cloud-cli` | WAITING_FOR_PREREQUISITE | `arsenal-cloud-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser; provision arsenal-cloud-lab: local cloud emulator or explicitly supplied controlled cloud account |
| `skopeo/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `spotbugs/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
| `ssh-audit/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `subfinder/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `syft/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
| `testssl-sh/linux-cli` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `web-ext/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
| `websocat/network-lab` | UNAVAILABLE | `arsenal-network-lab` | `` | binary not found | install and pin runtime; add deterministic positive/negative fixture; connect native-output parser |
| `yara/linux-cli` | UNAVAILABLE | `arsenal-binary` | `` | binary not found | install and pin runtime; connect native-output parser |
| `zizmor/linux-cli` | UNAVAILABLE | `arsenal-linux` | `` | binary not found | install and pin runtime; connect native-output parser |
