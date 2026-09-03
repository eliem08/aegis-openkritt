# Aegis Runtime Migrations and Deduplication Registry

Provenance-preserving formal records of superseded and deduplicated arsenal backends.

| Old Runtime | Replacement Runtime | Capabilities Affected | Reason | Date |
|---|---|---|---|---|
| firmadyne/qemu-lab | firmae/qemu-lab | asset:firmadyne/firmware-emulation-fallback | FirmAE is the direct automated successor that wraps and integrates Firmadyne core emulation components. Registering both as distinct external runtimes was an accidental double-counting of the same underlying QEMU firmware emulation engine. | 2026-09-03 |
| class-dump/macos-cli | otool/macos-cli | asset:class-dump/objective-c-interface-recovery | Original Steve Nygard class-dump v3.5 is 32/early-64-bit and obsolete on modern macOS Darwin arm64/x86_64 runtimes. Modern macOS Xcode otool natively provides complete Objective-C class, method, and protocol recovery through `otool -ov`. | 2026-09-03 |
