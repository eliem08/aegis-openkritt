# Runtime Migrations

Evidence Code SHA: `e56d4dae219c73f4efadff7c41688e31bc166c7c`
Report Commit SHA: `e56d4dae219c73f4efadff7c41688e31bc166c7c`
Validated PR Head SHA: `e56d4dae219c73f4efadff7c41688e31bc166c7c`
Git SHA: `e56d4dae219c73f4efadff7c41688e31bc166c7c`
Generated At: `2026-09-06T14:20:56.602036+00:00`

| Old Runtime | Replacement | Reason | In Execution Denominator |
|---|---|---|---|
| `firmadyne/qemu-lab` | `firmae/qemu-lab` | FirmAE is the direct automated successor that wraps and integrates Firmadyne core emulation components. Registering both as distinct external runtimes was an accidental double-counting of the same underlying QEMU firmware emulation engine. | No (Migrated) |
| `class-dump/macos-cli` | `otool/macos-cli` | Original Steve Nygard class-dump v3.5 is 32/early-64-bit and obsolete on modern macOS Darwin arm64/x86_64 runtimes. Modern macOS Xcode otool natively provides complete Objective-C class, method, and protocol recovery through `otool -ov`. | No (Migrated) |
