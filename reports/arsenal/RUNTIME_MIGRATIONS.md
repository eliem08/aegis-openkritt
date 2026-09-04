# Runtime Migrations

Git SHA: `97331ee62ae558421929d2c9c5eb1848210bd576`
Generated At: `2026-09-04T01:08:00.386832+00:00`

| Old Runtime | Replacement | Reason | In Execution Denominator |
|---|---|---|---|
| `firmadyne/qemu-lab` | `firmae/qemu-lab` | FirmAE is the direct automated successor that wraps and integrates Firmadyne core emulation components. Registering both as distinct external runtimes was an accidental double-counting of the same underlying QEMU firmware emulation engine. | No (Migrated) |
| `class-dump/macos-cli` | `otool/macos-cli` | Original Steve Nygard class-dump v3.5 is 32/early-64-bit and obsolete on modern macOS Darwin arm64/x86_64 runtimes. Modern macOS Xcode otool natively provides complete Objective-C class, method, and protocol recovery through `otool -ov`. | No (Migrated) |
