# Never-Executed Arsenal Backends

Git SHA: `97331ee62ae558421929d2c9c5eb1848210bd576`
Generated At: `2026-09-04T01:08:00.386832+00:00`
Backlog Count: **11**

The following active backends require dedicated physical or external infrastructure prerequisites and have not been falsely credited:

| Backend ID | Prerequisite Required | Runner |
|---|---|---|
| `external:azurehound` | local Entra fixture or explicitly supplied controlled tenant | `arsenal-cloud-lab` |
| `external:firmae` | opt-in privileged Linux worker with FirmAE/QEMU/binfmt; readiness: test -e /dev/kvm && command -v qemu-system-x86_64 && test -d /opt/FirmAE | `arsenal-firmware` |
| `external:frida` | operator-owned local emulator/device and fixture app; readiness: adb devices && frida-ps -U | `arsenal-android` |
| `external:gau` |  | `arsenal-network-lab` |
| `external:mobsf` | loopback MobSF service and synthetic APK; readiness: test -n "$AEGIS_MOBSF_URL" && curl -fsS "$AEGIS_MOBSF_URL/api/v1/scans" | `arsenal-android` |
| `external:objection` | Frida-capable operator-owned emulator/device; readiness: adb devices && frida-ps -U && objection --version | `arsenal-android` |
| `external:otool` | macOS worker; readiness: command -v otool && uname -s | grep Darwin | `arsenal-macos-ios` |
| `external:prowler` | local cloud emulator or explicitly supplied controlled cloud account | `arsenal-cloud-lab` |
| `external:roadrecon` | local Entra fixture or explicitly supplied controlled tenant | `arsenal-cloud-lab` |
| `external:scout` | local cloud emulator or explicitly supplied controlled cloud account | `arsenal-cloud-lab` |
| `external:subfinder` |  | `arsenal-network-lab` |
