# Applications

Go/Fyne desktop apps for macOS, Linux and Windows, plus a native UIKit iOS app.

From the repository root:

```sh
just dev                 # Run the desktop app
just ios                 # Build iOS payloads on macOS
just release             # Package the current platform
just release all         # Package supported targets
```

Sign in, select a trusted iPhone, choose an IPA and install. **Set Up IPA Loader**
installs the iOS app. Account settings manage saved accounts, teams and certificates.
Cancellation cannot undo an installation already submitted to the phone.

Builds need Go and platform toolchains: Xcode on macOS, Zig and a Darwin-capable
LLVM linker for Windows cross-builds, and Docker for Linux builds from macOS.
Linux/Windows packages require the iOS payloads built on macOS.
See [the iOS guide](IOS.md) for setup and refresh.

Signing supports arm64/arm64e iPhone apps, frameworks, dylibs and basic extensions.
Sharing-adapter injection requires thin arm64 images. Encrypted binaries,
simulator/32-bit slices and unsupported entitlements are rejected.

Tests, from the repository root:

```sh
go -C app test -race -tags ci ./...
```

`cmd/` contains entry points and build utilities; `internal/` contains application
code and tests. `scripts/` holds build recipes, `ios/` the packet tunnel, and
`licenses/` release attribution.
