# Arsenal runner matrix

| Runner | Platform | State | Missing prerequisites | Runtime count |
|---|---|---|---|---:|
| `arsenal-core` | any | **READY** | - | 0 |
| `arsenal-linux` | linux | **WAITING_FOR_PREREQUISITE** | command:docker, unverified-runtimes:8 | 30 |
| `arsenal-network-lab` | linux | **WAITING_FOR_PREREQUISITE** | command:docker, unverified-runtimes:10 | 17 |
| `arsenal-android` | linux | **WAITING_FOR_PREREQUISITE** | command:adb, command:emulator, environment:ANDROID_HOME, unverified-runtimes:4 | 5 |
| `arsenal-firmware` | linux | **WAITING_FOR_PREREQUISITE** | command:docker, command:qemu-system-x86_64, privileged-runner-approval, unverified-runtimes:2 | 3 |
| `arsenal-binary` | linux | **WAITING_FOR_PREREQUISITE** | command:file, unverified-runtimes:3 | 7 |
| `arsenal-smart-contract` | linux | **READY** | - | 4 |
| `arsenal-kubernetes` | linux | **WAITING_FOR_PREREQUISITE** | command:docker, command:kubectl, command:kind, unverified-runtimes:1 | 1 |
| `arsenal-cloud-lab` | linux | **WAITING_FOR_PREREQUISITE** | environment:AEGIS_CLOUD_LAB_AUTHORIZATION, unverified-runtimes:5 | 5 |
| `arsenal-macos-ios` | macos | **WAITING_FOR_PREREQUISITE** | requires macos runner, command:xcrun, command:xcodebuild, command:otool, unverified-runtimes:2 | 2 |
| `arsenal-llm` | any | **READY** | - | 0 |
| `arsenal-postgres` | any | **WAITING_FOR_PREREQUISITE** | environment:AEGIS_ARSENAL_COVERAGE_DB_URL | 0 |
