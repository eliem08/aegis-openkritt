# Arsenal runner matrix

| Runner | Platform | State | Missing prerequisites | Runtime count |
|---|---|---|---|---:|
| `arsenal-core` | any | **READY** | - | 0 |
| `arsenal-linux` | linux | **WAITING_FOR_PREREQUISITE** | unverified-runtimes:17 | 30 |
| `arsenal-network-lab` | linux | **WAITING_FOR_PREREQUISITE** | unverified-runtimes:17 | 17 |
| `arsenal-android` | linux | **WAITING_FOR_PREREQUISITE** | environment:ANDROID_HOME, unverified-runtimes:5 | 5 |
| `arsenal-firmware` | linux | **WAITING_FOR_PREREQUISITE** | privileged-runner-approval, unverified-runtimes:3 | 3 |
| `arsenal-binary` | linux | **WAITING_FOR_PREREQUISITE** | unverified-runtimes:7 | 7 |
| `arsenal-smart-contract` | linux | **WAITING_FOR_PREREQUISITE** | unverified-runtimes:2 | 4 |
| `arsenal-kubernetes` | linux | **WAITING_FOR_PREREQUISITE** | unverified-runtimes:1 | 1 |
| `arsenal-cloud-lab` | linux | **WAITING_FOR_PREREQUISITE** | environment:AEGIS_CLOUD_LAB_AUTHORIZATION, unverified-runtimes:5 | 5 |
| `arsenal-macos-ios` | macos | **WAITING_FOR_PREREQUISITE** | requires macos runner, command:xcrun, command:xcodebuild, command:otool, unverified-runtimes:2 | 2 |
| `arsenal-llm` | any | **READY** | - | 0 |
| `arsenal-postgres` | any | **WAITING_FOR_PREREQUISITE** | environment:AEGIS_ARSENAL_COVERAGE_DB_URL | 0 |
