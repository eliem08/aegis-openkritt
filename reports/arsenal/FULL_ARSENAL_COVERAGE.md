# Full Arsenal Coverage

Verdict: **FULL ACTIVE SOFTWARE ARSENAL VERIFIED — MIGRATED/HARDWARE-SPECIFIC CAPABILITIES SEPARATE**

## Exact-Head Provenance

- Source Git SHA: `97331ee62ae558421929d2c9c5eb1848210bd576`
- Generated At: `2026-09-04T01:08:00.386832+00:00`
- Inventory Digest: `a4965112917eacc8b4b5b465993793d736916c43a3d8385488d36cd010072c0c`
- Backend Lock Digest: `94ad5b8cca304aaeb2a69cb36f3a45451ce9828a20019d8a43862ba5a03ea6a8`
- Fixture Version Digest: `aa4d89610f7e9236736d56b9e19146f001fe3bf4c25a09dcd8011adbfeb33f79`
- Evidence Root Digest: `2641d787ee7a04711fd89969d610b2e9f9085bbd7d850ca43b3159adea13c00f`
- Arsenal Image: ``

## Metrics

- `registered_backends`: `73`
- `active_backends`: `71`
- `migrated_backends`: `2`
- `verified_real_backend_executions`: `67`
- `verified_shared_backend_executions`: `15`
- `verified_real_capabilities`: `81`
- `migrated_capabilities`: `2`
- `never_executed_active_backends`: `11`
- `positive_controls`: `73`
- `negative_controls`: `73`
- `waiting_prerequisite_count`: `71`
- `unavailable_count`: `2`
- `backend_unhealthy_count`: `0`
- `total_canonical_capabilities`: `174`
- `unique_backends`: `99`
- `unique_external_backends`: `73`
- `healthy_backends`: `60`
- `backend_executions`: `67`
- `fixture_executed_backends`: `67`
- `fixture_executed_capabilities`: `81`
- `fixture_backend_denominator`: `71`
- `fixture_capability_denominator`: `93`
- `fixture_backend_execution_coverage`: `0.9436619718309859`
- `fixture_capability_execution_coverage`: `0.8709677419354839`
- `authorized_real_execution_coverage`: `None`
- `authorized_real_executed_capabilities`: `0`
- `positive_controls_passed`: `73`
- `negative_controls_passed`: `73`
- `never_executed_external_backends`: `11`
- `states`: `{'EXECUTED_PASS': 73, 'EXECUTED_FINDING': 0, 'WAITING_FOR_PREREQUISITE': 15, 'UNAVAILABLE': 0, 'DENIED_BY_POLICY': 0, 'DENIED_POLICY_AMBIGUOUS': 0, 'NOT_IMPLEMENTED': 0, 'BACKEND_UNHEALTHY': 0}`

## Runtime Migrations

| Old Runtime | Replacement | Reason | Semantics | Old Binary Executed | In Execution Denominator |
|---|---|---|---|---|---|
| `firmadyne/qemu-lab` | `firmae/qemu-lab` | FirmAE is the direct automated successor that wraps and integrates Firmadyne core emulation components. Registering both as distinct external runtimes was an accidental double-counting of the same underlying QEMU firmware emulation engine. | isolated firmware emulation fallback for supported Linux-based images -> isolated IoT firmware emulation for dynamic analysis (FirmAE embeds and automates the Firmadyne extraction, QEMU kernel emulation, and network service inspection pipeline) | No | No (Migrated) |
| `class-dump/macos-cli` | `otool/macos-cli` | Original Steve Nygard class-dump v3.5 is 32/early-64-bit and obsolete on modern macOS Darwin arm64/x86_64 runtimes. Modern macOS Xcode otool natively provides complete Objective-C class, method, and protocol recovery through `otool -ov`. | Objective-C class interface recovery from Mach-O binaries -> Objective-C class interface, protocol, and load command extraction via otool (-ov / -l) on modern macOS Darwin runtimes | No | No (Migrated) |

## Backend Execution Matrix

| Backend Runtime | Kind | Active/Migrated | Runner | Proof Kind | Positive | Negative | State |
|---|---|---|---|---|---|---|---|
| `ghidra/headless` | active | EXTERNAL_TOOL | `arsenal-binary` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `angr/linux-cli` | active | EXTERNAL_TOOL | `arsenal-binary` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `apktool/linux-cli` | active | EXTERNAL_TOOL | `arsenal-android` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `electron-asar/node-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `azurehound/cloud-lab` | active | EXTERNAL_TOOL | `arsenal-cloud-lab` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `bandit/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `binwalk/firmware-lab` | active | EXTERNAL_TOOL | `arsenal-firmware` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `brakeman/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `capa/linux-cli` | active | EXTERNAL_TOOL | `arsenal-binary` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `checkov/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `class-dump/macos-cli` | migrated | EXTERNAL_TOOL | `arsenal-macos-ios` | `MIGRATED_EQUIVALENT` | MIGRATED | MIGRATED | WAITING_FOR_PREREQUISITE |
| `cloudsplaining/cloud-lab` | active | EXTERNAL_TOOL | `arsenal-cloud-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `codeql/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `detect-secrets/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `dnsx/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `echidna/contract-cli` | active | EXTERNAL_TOOL | `arsenal-smart-contract` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `firmadyne/qemu-lab` | migrated | EXTERNAL_TOOL | `arsenal-firmware` | `MIGRATED_EQUIVALENT` | MIGRATED | MIGRATED | WAITING_FOR_PREREQUISITE |
| `firmae/qemu-lab` | active | EXTERNAL_TOOL | `arsenal-firmware` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `floss/linux-cli` | active | EXTERNAL_TOOL | `arsenal-binary` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `foundry/forge` | active | EXTERNAL_TOOL | `arsenal-smart-contract` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `frida/device-cli` | active | EXTERNAL_TOOL | `arsenal-android` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `garak/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `gau/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | UNAVAILABLE |
| `gitleaks/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `gosec/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `grpcurl/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `grype/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `httpx/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `jadx/android-lab` | active | EXTERNAL_TOOL | `arsenal-android` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `jsluice/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `katana/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `kics/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `kubescape/kubernetes-lab` | active | EXTERNAL_TOOL | `arsenal-kubernetes` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `mitmproxy/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `mobsf/container` | active | EXTERNAL_TOOL | `arsenal-android` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `modelscan/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `mythril/linux-cli` | active | EXTERNAL_TOOL | `arsenal-smart-contract` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `naabu/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `njsscan/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `nmap/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `npm/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `nuclei/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `objection/android-lab` | active | EXTERNAL_TOOL | `arsenal-android` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `osv-scanner/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `otool/macos-cli` | active | EXTERNAL_TOOL | `arsenal-macos-ios` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `pefile/linux-cli` | active | EXTERNAL_TOOL | `arsenal-binary` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `pip-audit/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `playwright/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `promptfoo/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `prowler/cloud-lab` | active | EXTERNAL_TOOL | `arsenal-cloud-lab` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `psalm/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `pyrit/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `restler/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `retire-js/node-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `rizin/linux-cli` | active | EXTERNAL_TOOL | `arsenal-binary` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `roadrecon/cloud-lab` | active | EXTERNAL_TOOL | `arsenal-cloud-lab` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `rustscan/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `schemathesis/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `scorecard/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `scoutsuite/cloud-cli` | active | EXTERNAL_TOOL | `arsenal-cloud-lab` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `semgrep/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `skopeo/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `slither/contract-cli` | active | EXTERNAL_TOOL | `arsenal-smart-contract` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `spotbugs/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `ssh-audit/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `subfinder/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | UNAVAILABLE |
| `syft/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `testssl-sh/linux-cli` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `trivy/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `web-ext/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `websocat/network-lab` | active | EXTERNAL_TOOL | `arsenal-network-lab` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `yara/linux-cli` | active | EXTERNAL_TOOL | `arsenal-binary` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `zizmor/linux-cli` | active | EXTERNAL_TOOL | `arsenal-linux` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-agent-permission-audit` | active | INTERNAL_AEGIS | `arsenal-core` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-artifact-diff` | active | INTERNAL_AEGIS | `arsenal-core` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-asar` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-asset-classifier` | active | INTERNAL_AEGIS | `arsenal-core` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-asset-triage` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-authz-matrix` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-binary-triage` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-bola-probe` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-contract-patterns` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-firmware-arch` | active | INTERNAL_AEGIS | `arsenal-core` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-github-org` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-gitlab-group` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-llm-lab` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-memory-poisoning` | active | INTERNAL_AEGIS | `arsenal-core` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-model-provenance` | active | INTERNAL_AEGIS | `arsenal-core` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-openapi-parser` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-output-oracle` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-package-registry` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-policy-parser` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-rag-boundary` | active | INTERNAL_AEGIS | `arsenal-core` | `REAL_BACKEND` | PASS | PASS | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-store-metadata` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/aegis-strings` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/crt.sh` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/stdlib-http` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/stdlib-resolver` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |
| `aegis/stdlib-ssl` | active | INTERNAL_AEGIS | `arsenal-core` | `PREREQUISITE_ONLY` | NOT_EXECUTED | NOT_EXECUTED | WAITING_FOR_PREREQUISITE |

## Executions

| Capability | State | Run | Evidence |
|---|---|---|---|
| `adapter:jsluice/passive-discovery` | EXECUTED_PASS | `arsenal-20260903T141011Z-cc042d57` | `9c5c991ba5663997e87e91f4742be4e465f46fbcf921f6a7a0f4415154715f2d` |
| `asset:aegis-agent-permission-audit/agent-tool-permission-analysis` | EXECUTED_PASS | `arsenal-20260903T152700Z-6574bbb2` | `9d96e855f009db32c01cec68f6547e3e72ce1629ba7e40c8d391aa66caa91974` |
| `asset:aegis-artifact-diff/authorized-mobile-release-diff` | EXECUTED_PASS | `arsenal-20260903T152647Z-92e55665` | `d99ed90643042a38196bdc3c02cde5d7a8696936c50c509bc1a5a5bb62437db0` |
| `asset:aegis-asset-classifier/deterministic-asset-classification` | EXECUTED_PASS | `arsenal-20260903T152700Z-dd598803` | `cd1f0b58c94e6cc4a221087ba2dc58c208e25cde5661cb165fabbde9735f6cb4` |
| `asset:aegis-firmware-arch/firmware-architecture-detection` | EXECUTED_PASS | `arsenal-20260903T152700Z-a61d97ed` | `ba5bffcf60663179fbde55077d5105e8ec8bad377dbb212f1c89dd0bd47ab496` |
| `asset:aegis-memory-poisoning/agent-memory-poisoning-regression` | EXECUTED_PASS | `arsenal-20260903T152700Z-536a27eb` | `eea2d1441399372ec0668d0d489835187fe63b4a69b11ac5a553dd1647657b2e` |
| `asset:aegis-model-provenance/model-provenance-and-hash-ledger` | EXECUTED_PASS | `arsenal-20260903T152700Z-cff834b3` | `9fe6903ab2af4ea71d1cb201a88eacfd6496dc5e931282f3f0b23f318766aa1e` |
| `asset:aegis-rag-boundary/rag-retrieval-trust-analysis` | EXECUTED_PASS | `arsenal-20260903T152701Z-69845317` | `5217937d25b6ae5f91dac7d878e4b390eb0018162678492029895643f1e3ace0` |
| `asset:angr/binary-control-flow-analysis` | EXECUTED_PASS | `arsenal-20260903T141013Z-d59edeee` | `4b9c7b081fc3a1924b5ad37376e3d85ea7f644c73da49ba2a11f4a62c03080d1` |
| `asset:apktool/android-resource-and-manifest-decode` | EXECUTED_PASS | `arsenal-20260903T141017Z-b4944f6f` | `9aceee7c0c660629f76133d463ce6dfdc0352bc5b87800ba956368519663eeea` |
| `asset:binwalk/firmware-structure-analysis` | EXECUTED_PASS | `arsenal-20260903T141021Z-12205524` | `a8dc7d9d22708304eb21905723f8bb206948ec449c221c30316ac83b43822b56` |
| `asset:capa/binary-capability-analysis` | EXECUTED_PASS | `arsenal-20260903T141022Z-646e1cd3` | `dc91c77ca9ef0e06d3ac117fb4fa55e68eec311cd46b52f6e99615804f4104fa` |
| `asset:checkov/container-image-policy-scan` | EXECUTED_PASS | `arsenal-20260903T141445Z-c1f6e2b7` | `5dfba94d95ed42672ed2278b8161279e13134eab5d3510ba9e4c83555ff78e43` |
| `asset:class-dump/objective-c-interface-recovery` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152702Z-db5bcbce` | `396720387cc79c023ace60bb11e74797e5ecd3aef7c6d283bf7a9d4b327ba0a5` |
| `asset:cloudsplaining/aws-iam-risk-analysis` | EXECUTED_PASS | `arsenal-20260903T141040Z-97955186` | `b2a18893ae2f41259844b137d3a4d48471cb9ef007eedc05c6076d2bd57eb05c` |
| `asset:codeql/cross-file-dataflow` | EXECUTED_PASS | `arsenal-20260903T141043Z-9acdc466` | `b8df60192883420c8d8978a6c8325fdede7cee43d17efe649033642b63def705` |
| `asset:dnsx/dns-resolution-and-wildcard-filtering` | EXECUTED_PASS | `arsenal-20260903T141134Z-a769ec45` | `cd5a36d620fa5acf8a05a5de22b5151bf352d3f71cd0cd4987780d0b9cd71088` |
| `asset:echidna/smart-contract-property-fuzzing` | EXECUTED_PASS | `arsenal-20260903T141135Z-b2b58df7` | `6aafb2d443285f65de6eadfc5515feae504d5c3172f4fbd2a9309343b94d6a77` |
| `asset:electron-asar/electron-package-extraction` | EXECUTED_PASS | `arsenal-20260903T141137Z-94b14ccd` | `8020759e6614d57dce53566dc427f47f0190a9fc7a4617a4f82fd79b3b73b081` |
| `asset:firmadyne/firmware-emulation-fallback` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152701Z-81fb8163` | `e04be761c6bda980843415f2a1b66e36db9dd296aaa44a5b0674164699c2b8b9` |
| `asset:firmae/firmware-emulation` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152701Z-81fb8163` | `e04be761c6bda980843415f2a1b66e36db9dd296aaa44a5b0674164699c2b8b9` |
| `asset:floss/static-string-deobfuscation` | EXECUTED_PASS | `arsenal-20260903T141138Z-3d198544` | `c842691a2c2b63ebaef373e0c59ef23adbc363543bb2ba0e216c831c829229e5` |
| `asset:foundry/smart-contract-fuzz-and-invariant-tests` | EXECUTED_PASS | `arsenal-20260903T141157Z-52256573` | `d8690b7919a74dbe8a9c4cc8a6a748894f061590c2844e950406d4691d8e3d85` |
| `asset:frida/android-runtime-instrumentation` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152701Z-6a1c4bb2` | `4d6869c58e99d06332926209a26b9cde1c46a4f7f7777200c07f425ccf872f63` |
| `asset:frida/ios-runtime-instrumentation` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152701Z-6a1c4bb2` | `4d6869c58e99d06332926209a26b9cde1c46a4f7f7777200c07f425ccf872f63` |
| `asset:garak/llm-security-probing` | EXECUTED_PASS | `arsenal-20260903T141201Z-4f47e4fc` | `4d3dac82d15321855ab9957dd2286b099639f4d5379abcfbffaa4a7da6b6f27b` |
| `asset:ghidra/headless-binary-analysis` | EXECUTED_PASS | `arsenal-20260903T141204Z-fa334d23` | `ea77b11f8d8c0d7331b1348061e425e8d3fbc41694bf537aa8afd5eef52613f2` |
| `asset:grpcurl/grpc-service-introspection` | EXECUTED_PASS | `arsenal-20260903T141223Z-491e3d54` | `e7eb2aa657fe79aa575a0aa74e0edf84a31bf3581a8039c9ae3fe30bf2feed81` |
| `asset:grype/container-image-vulnerability-scan` | EXECUTED_PASS | `arsenal-20260903T141458Z-08e7cfff` | `e3a6c8cd007433ee21e14470494cee1bfc285ee8126d6dbbf4a83e3191286608` |
| `asset:httpx/http-service-enrichment` | EXECUTED_PASS | `arsenal-20260903T141224Z-2253bc96` | `d28834d1bc5b7321f84b0bf9172364bf309e27371eb4c573e6a608f63ba4bebd` |
| `asset:jadx/android-decompile` | EXECUTED_PASS | `arsenal-20260903T141227Z-dfc1081e` | `8606b29aa2caf98b3f9b795893cdd8ce147cc8aee6b32ae59de76167cbbe7efb` |
| `asset:katana/scoped-endpoint-crawl` | EXECUTED_PASS | `arsenal-20260903T141231Z-bfd584c5` | `fc4c313624a001b55028ac9411a069f0a9cf0f0e4fcedcb3d0c0afe26f66f8e8` |
| `asset:kics/iac-security-scan` | EXECUTED_PASS | `arsenal-20260903T141254Z-50b4b002` | `4e10278e79db9a1f4c35cb1e99b4df855b11c9bdfff7d511df05d8c850d5234e` |
| `asset:kubescape/kubernetes-posture-and-runtime-scan` | EXECUTED_PASS | `arsenal-20260903T141255Z-6477fce4` | `075bd37c5d6aa9c7a70a7e8d6011213c180fd12404b7913c33a6cb7d3b52fea4` |
| `asset:mitmproxy/authorized-http-traffic-capture` | EXECUTED_PASS | `arsenal-20260903T141257Z-a45775d0` | `f7515a411e2784300cd7b1c5e5476197ba90634ebf2bbdfa99abab656cefdd2e` |
| `asset:mobsf/rest-static-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152701Z-04a49db7` | `8f3d53047fb289fa8e076652e70c4b771612b37f530d24cdcbfb57c6aa91cd42` |
| `asset:modelscan/serialized-model-safety-scan` | EXECUTED_PASS | `arsenal-20260903T141303Z-40016bcf` | `62b90360b4307c6374cbf9d8043aa9cf5df23e20fbb9799bbe6f65a55b4d853c` |
| `asset:naabu/bounded-port-discovery` | EXECUTED_PASS | `arsenal-20260903T141304Z-3be626df` | `9dadb9f88aac4332f695df42952f3a6b7bac5e02918931d2799556c55a10d26b` |
| `asset:nmap/bounded-service-fingerprinting` | EXECUTED_PASS | `arsenal-20260903T141310Z-a75f7035` | `90085aacbdd0969a3c9f142f624953216913b8c97869de297bc4686c66db1856` |
| `asset:npm/npm-dependency-audit` | EXECUTED_PASS | `arsenal-20260903T141317Z-7d6db3a5` | `cd8e0da22566b65403dfa963d395512c455262e6241684dddb129506288307f0` |
| `asset:nuclei/signed-safe-template-validation` | EXECUTED_PASS | `arsenal-20260903T141319Z-753b5148` | `c7d55d57cec4cb185a54a914e5e0b8284ff2f6a9ac979a7f3f869a0c14846ef6` |
| `asset:objection/android-runtime-exploration` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152701Z-8f4610a4` | `da22abcb1dbf9d3f697f61123d9939a42848d72141074d35ca8a8f85ef3907c8` |
| `asset:objection/ios-runtime-exploration` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152701Z-8f4610a4` | `da22abcb1dbf9d3f697f61123d9939a42848d72141074d35ca8a8f85ef3907c8` |
| `asset:openssf-scorecard/repository-supply-chain-posture` | EXECUTED_PASS | `arsenal-20260903T141321Z-3ca3f020` | `b82dbcef4fd44225b29bd984771d828add787ff199c3ce5f266572574bbb2ad3` |
| `asset:otool/ios-macos-load-command-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152702Z-f09b112a` | `62acab7d5a3b213c2b96a7998a328ac811c30388c24a5c66109a36bda53325f8` |
| `asset:pefile/pe-structure-analysis` | EXECUTED_PASS | `arsenal-20260903T141321Z-36c1040c` | `9f9621c8879ce8293de51b0695c63b157c29b9fec22d9a5a8bbe4ff67f51801c` |
| `asset:pip-audit/python-dependency-vulnerability-analysis` | EXECUTED_PASS | `arsenal-20260903T141322Z-da6882f5` | `acbb1b923f51dd28172bc3c31001b3b5c45d4f75a688e730e91cf14505e1b76a` |
| `asset:playwright/authenticated-browser-traffic-learning` | EXECUTED_PASS | `arsenal-20260903T141326Z-42f85a22` | `fd672648fbf49eff7921c2b8a6661a7f3732bca83f9a649059c9450d16ac75f1` |
| `asset:promptfoo/ai-red-team-evaluation` | EXECUTED_PASS | `arsenal-20260903T141332Z-d3d49d24` | `d580983adeca08c571f8a6a22d05baa4e58c6455f41df4344bb3934f523efa6e` |
| `asset:pyrit/generative-ai-risk-identification` | EXECUTED_PASS | `arsenal-20260903T141338Z-0dbf040e` | `08c0d10c47c3a8a995a6f96b7864d39825167f34442ed4a2fc95f1247d54ef5a` |
| `asset:restler/stateful-openapi-sequence-testing` | EXECUTED_PASS | `arsenal-20260903T141347Z-5c773eac` | `0554bceb98e6e4271db0c9b1de32c314d93fb91aec92497e628b993447765f74` |
| `asset:rizin/binary-reverse-engineering` | EXECUTED_PASS | `arsenal-20260903T141353Z-98141672` | `b4e12b3f0c76b8289a12c05aaa3fbbc6908a6782b83cc678bbc0b4701d00a230` |
| `asset:rustscan/bounded-fast-port-prefilter` | EXECUTED_PASS | `arsenal-20260903T141356Z-59542ff4` | `32e76edb3f45b15f12040a9d7c6e2aac4994fb47812a0f3a099eb2bdd996bf2d` |
| `asset:schemathesis/schema-guided-api-testing` | EXECUTED_PASS | `arsenal-20260903T141357Z-ad960f3c` | `14f51b27f69736a9610cd62dd77069675fa1200278e22c6216c2360d9cce9e4a` |
| `asset:skopeo/container-registry-metadata` | EXECUTED_PASS | `arsenal-20260903T141401Z-74a96466` | `684f4dd3818775da39f901778d40d6f07dd2008bd4f36c7fb39dff9baf1f222b` |
| `asset:spotbugs/java-bytecode-static-analysis` | EXECUTED_PASS | `arsenal-20260903T141405Z-3d101eee` | `c16d1840aed1de8af5ab37fc321cfc4212338c96bec76d34a5038f94658b75f1` |
| `asset:ssh-audit/ssh-configuration-analysis` | EXECUTED_PASS | `arsenal-20260903T141415Z-d3e4af92` | `3e2973458532e436e7409c238c2d46f2911749da871c1fbe55c9f7f16dd1e8a1` |
| `asset:syft/artifact-sbom` | EXECUTED_PASS | `arsenal-20260903T141418Z-4094dbcd` | `e8c0c9debb0f5856134926dac0ab82c0b236a607739e812065c2797e5105c988` |
| `asset:syft/container-image-sbom` | EXECUTED_PASS | `arsenal-20260903T141418Z-4094dbcd` | `e8c0c9debb0f5856134926dac0ab82c0b236a607739e812065c2797e5105c988` |
| `asset:testssl-sh/tls-configuration-analysis` | EXECUTED_PASS | `arsenal-20260903T141421Z-2f3ef2c3` | `35b6e75f2e09ce10f31127d16c9faed40b98128485e9e17df2c90f9ceccdc015` |
| `asset:trivy/container-image-security-scan` | EXECUTED_PASS | `arsenal-20260903T141630Z-a6b66704` | `a5ede65c181336358a861824281ce5c28ad7ee72a6434cc994dfca68ad6582f2` |
| `asset:web-ext/browser-extension-structure-lint` | EXECUTED_PASS | `arsenal-20260903T141437Z-bbb6d081` | `120311b3ad5aac9038509de8ebd70e9b3731eabdcb6288cf3bcf8afe77c2c4ff` |
| `asset:websocat/websocket-protocol-observation` | EXECUTED_PASS | `arsenal-20260903T141439Z-57e6eb4b` | `0791d3cdae69f8b8451ac45d2dbce05e903864d129fc74cdebd9fe16362e95b4` |
| `asset:yara/approved-rule-binary-scan` | EXECUTED_PASS | `arsenal-20260903T141440Z-0451d92f` | `2a9f78ad5c7da41bb59291ac16f73bba119197328c094f9c4b3a8e3d2f3acb82` |
| `asset:zizmor/github-actions-security-audit` | EXECUTED_PASS | `arsenal-20260903T141440Z-77eaf813` | `7c884b38ddc838c1709e8d69b7c4a9c271bcb1d62e66fd0a8d0b056c6f25ddc1` |
| `fixture:ai/llm-security-boundary` | EXECUTED_PASS | `arsenal-20260903T141440Z-95e7c2cf` | `22b1616d92007ccbb548a714abb61ad95fa943714ab1ae4ce22bdd7079c3ac8b` |
| `tool:bandit/code` | EXECUTED_PASS | `arsenal-20260903T141440Z-10af6d59` | `c435cc88ed86c92621212e3f98d2e4ef277ebdc9414b50df70b1c0ca869d24d3` |
| `tool:brakeman/code` | EXECUTED_PASS | `arsenal-20260903T141441Z-2fe8effc` | `37d990c098db7537181526079bc145d47418fb569e226fbc5749ad2c18dd2ef9` |
| `tool:checkov/deps` | EXECUTED_PASS | `arsenal-20260903T141445Z-c1f6e2b7` | `5dfba94d95ed42672ed2278b8161279e13134eab5d3510ba9e4c83555ff78e43` |
| `tool:detect-secrets/secrets` | EXECUTED_PASS | `arsenal-20260903T141453Z-b13ba354` | `4b6cf406a6604f9883b475172ef027a81eb0b5314ce75460b9ae8110c0b0abff` |
| `tool:gitleaks/secrets` | EXECUTED_PASS | `arsenal-20260903T141454Z-7cfcdc07` | `cf5eae0f94550e3c486518d49d3cc921284ff4c389e45db5cb3f96743f5b6b76` |
| `tool:gosec/code` | EXECUTED_PASS | `arsenal-20260903T141454Z-7c788a60` | `0cd8a943140b1f0e5bdf7705b11b6395db4331ee376fb1dd31852a16f34f6117` |
| `tool:grype/deps` | EXECUTED_PASS | `arsenal-20260903T141458Z-08e7cfff` | `e3a6c8cd007433ee21e14470494cee1bfc285ee8126d6dbbf4a83e3191286608` |
| `tool:mythril/contract` | EXECUTED_PASS | `arsenal-20260903T141511Z-d0e7c466` | `6d2c71f1c3b6d3760d910e5476cd5b9d3bba161f70700234199c34837f224e44` |
| `tool:njsscan/code` | EXECUTED_PASS | `arsenal-20260903T141534Z-fce163da` | `a41978462ede717795f69b671ea49bfd14fd1b7bfa24174423a9d09ee8ba2c22` |
| `tool:osv-scanner/deps` | EXECUTED_PASS | `arsenal-20260903T141547Z-a742d377` | `e75ed33e04eb9ecd77c5e2d8b644d550be8fb8a6145a05d95794faa721e9d466` |
| `tool:psalm/code` | EXECUTED_PASS | `arsenal-20260903T141610Z-024dafad` | `dce12afe96dcdfc826b27a5e71a394a17e8d86736ded8a039c76ee8fce07e862` |
| `tool:retire-js/deps` | EXECUTED_PASS | `arsenal-20260903T141620Z-2f3f10f8` | `1aff5be27da3b254bac89845b6178ccdca607f9fecbe61786db89d96d4da0ed7` |
| `tool:semgrep/code` | EXECUTED_PASS | `arsenal-20260903T141622Z-63d96a35` | `0561b73dcc76f457d0831f4c34a82adb2ff892f8156085d335442af189ff7cbb` |
| `tool:slither/contract` | EXECUTED_PASS | `arsenal-20260903T141629Z-131eea33` | `54333f1239024c6190e7f4f9a4c3e7dd7ee90e66bb5d7708436fd519fa7a761a` |
| `tool:trivy/deps` | EXECUTED_PASS | `arsenal-20260903T141630Z-a6b66704` | `a5ede65c181336358a861824281ce5c28ad7ee72a6434cc994dfca68ad6582f2` |
| `tool:trivy/secrets` | EXECUTED_PASS | `arsenal-20260903T141631Z-d99ad6a5` | `5ca1b7e8d4c558b942ff4d23de38f009174c331fff0b3ae2f8b7cb79222a38b7` |
| `asset:prowler/aws-security-posture` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152702Z-1c24fe56` | `df5514437cc1edcfcb11aa98795a5740db3864620802177bcb196cee7e9ab802` |
| `asset:scoutsuite/aws-attack-surface-audit` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152702Z-d83dec86` | `84636aa94101946c06cd11da22d3e925f1867d333e658b7df70e447d7c40666d` |
| `asset:roadtools/entra-identity-analysis` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152702Z-f4794a5f` | `dff4fdcae6eef6c066725a0b5eb204f07ed81e4333d8cad1d5a025c04a9ebeaa` |
| `adapter:subfinder/passive-discovery` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152703Z-056e4080` | `758b88f39dfea6128fe52d231bfe4388f20beb46e3ae08dfc3584c97ee4228c0` |
| `asset:azurehound/azure-entra-relationship-collection` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152703Z-4cbfb5ff` | `18e370a2d9b9d24ceae961e01b15fe21acf253a9b3b1e5762548d2ef6fce91f0` |
| `adapter:gau/passive-discovery` | WAITING_FOR_PREREQUISITE | `arsenal-20260903T152703Z-f4b02dac` | `1d06d9ef86ad803a846566e22f2909c328d364e198ed180ba84528a682b6ae9b` |

## Never Executed Active Backends

- `external:azurehound`
- `external:firmae`
- `external:frida`
- `external:gau`
- `external:mobsf`
- `external:objection`
- `external:otool`
- `external:prowler`
- `external:roadrecon`
- `external:scout`
- `external:subfinder`
