# Runtime Migrations

Git SHA: `976a80b94d0c184b0ebb3493847305da708efafc`
Generated At: `2026-09-04T02:47:04.652331+00:00`

| Old Runtime | Replacement | Reason | In Execution Denominator |
|---|---|---|---|
| `firmadyne/qemu-lab` | `firmae/qemu-lab` | FirmAE is the direct automated successor that wraps and integrates Firmadyne core emulation components. Registering both as distinct external runtimes was an accidental double-counting of the same underlying QEMU firmware emulation engine. | No (Migrated) |
| `class-dump/macos-cli` | `otool/macos-cli` | Original Steve Nygard class-dump v3.5 is 32/early-64-bit and obsolete on modern macOS Darwin arm64/x86_64 runtimes. Modern macOS Xcode otool natively provides complete Objective-C class, method, and protocol recovery through `otool -ov`. | No (Migrated) |
