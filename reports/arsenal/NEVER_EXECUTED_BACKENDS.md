# Never-Executed Arsenal Backends

Git SHA: `976a80b94d0c184b0ebb3493847305da708efafc`
Generated At: `2026-09-04T02:47:04.652331+00:00`
Backlog Count: **10**

The following active backends require dedicated physical or external infrastructure prerequisites and have not been falsely credited:

| Backend ID | Missing Prerequisite | Why Not Executed | Infrastructure Needed | Provisionable | Real Target Needed | Proof Kind |
|---|---|---|---|---|---|---|
| `external:azurehound` | Dedicated operator-owned Entra ID / Azure tenant with synthetic test users, groups, and graph relationships | Requires authenticated Entra ID graph collector against operator-owned tenant; synthetic Python graph mock prohibited | Operator-owned Azure sandbox tenant with test app registration | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:firmae` | Privileged Linux KVM runner with /dev/kvm, QEMU system emulation, and FirmAE automation stack | Standard unprivileged runner lacks KVM acceleration and nested virtualization needed for FirmAE full system emulation | Bare-metal or KVM-enabled Linux self-hosted runner with FirmAE stack | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:frida` | Booted Android AVD emulator (API 30+ x86_64) with adb wait-for-device, frida-server deployed, and fixture APK | Standard runner does not boot Android emulator or start frida-server; Python-only wrapper rejected under process identity rules | KVM-capable Android emulator runner with matching frida-server binary and fixture APK | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:gau` | Native gau binary and operator-owned test domain with deterministic provider mock or query budget | Native gau executable not run against arbitrary third-party targets; Python wrapper rejected | Pinned gau binary on runner with operator-owned test domain | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:mobsf` | Live MobSF REST service container listening on loopback with API health check and real APK upload | Live MobSF container was not booted in standard runner; pre-recorded JSON / Python mock rejected | MobSF container image (opensecurity/mobile-security-framework-mobsf) | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:objection` | Live Frida session attached to running synthetic Android fixture process in booted emulator | Requires live Android emulator and Frida-backed session; Python fixture rejected | Booted Android AVD + frida-server + objection CLI | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:prowler` | Operator-owned disposable AWS/Azure sandbox account or certified LocalStack cloud emulator with signed ExecutionGrant | Requires authenticated cloud provider sandbox; string-flag authorization rejected | Signed ExecutionGrant + operator-owned AWS sandbox account / LocalStack Pro | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:roadrecon` | Dedicated operator-owned Entra ID tenant fixture with roadrecon auth and gather database | Requires operator-owned test tenant; arbitrary third-party tenant data prohibited | Operator-owned disposable Entra ID tenant with test user data | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:scout` | Operator-owned disposable cloud sandbox account with real ScoutSuite executable invocation | Requires live cloud provider credentials in operator-owned sandbox | Signed ExecutionGrant + operator-owned cloud account | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
| `external:subfinder` | Native subfinder binary executed in passive mode strictly against operator-owned test domain | Native subfinder invocation with query budget on operator-owned domain required; Python mock rejected | Pinned subfinder binary on runner with operator-owned test domain | Yes | No (Operator-Owned Sandbox) | `PREREQUISITE_ONLY` |
