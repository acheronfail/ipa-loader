# Sharing cross-build declarations

Public API declarations and linker stubs used to compile `sharing.m` outside
macOS. Implementations resolve from iOS at runtime.

On Windows, use `app/scripts/build-sharing-windows.ps1` with Zig and a Darwin-capable
LLVM linker (`ld64.lld` or `rust-lld`). Target `aarch64-ios.12.0`; the application
signs the resulting arm64 adapter during installation.
