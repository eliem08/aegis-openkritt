# Arsenal runner matrix

| Runner | Platform | State | Missing prerequisites | Runtime count |
|---|---|---|---|---:|
| `arsenal-core` | any | **READY** | - | 0 |
| `arsenal-linux` | linux | **READY** | - | 30 |
| `arsenal-network-lab` | linux | **READY** | - | 14 |
| `arsenal-android` | linux | **WAITING_FOR_PREREQUISITE** | environment:ANDROID_HOME | 5 |
| `arsenal-firmware` | linux | **WAITING_FOR_PREREQUISITE** | privileged-runner-approval | 3 |
| `arsenal-binary` | linux | **READY** | - | 7 |
| `arsenal-smart-contract` | linux | **READY** | - | 4 |
| `arsenal-kubernetes` | linux | **READY** | - | 1 |
| `arsenal-cloud-lab` | linux | **WAITING_FOR_PREREQUISITE** | environment:AEGIS_CLOUD_LAB_AUTHORIZATION | 5 |
| `arsenal-macos-ios` | macos | **WAITING_FOR_PREREQUISITE** | requires macos runner, command:xcrun, command:xcodebuild, command:otool | 2 |
| `arsenal-llm` | any | **READY** | - | 0 |
| `arsenal-postgres` | any | **WAITING_FOR_PREREQUISITE** | environment:AEGIS_ARSENAL_COVERAGE_DB_URL | 0 |
| `arsenal-passive-provider` | any | **WAITING_FOR_PREREQUISITE** | environment:AEGIS_PASSIVE_PROVIDER_AUTHORIZATION | 2 |
