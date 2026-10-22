set working-directory := "app"
set windows-shell := ["pwsh.exe", "-NoLogo", "-NoProfile", "-Command"]

export GOMODCACHE := justfile_directory() / "app/.cache/gomod"
export GOCACHE := justfile_directory() / "app/.cache/build"
export GOPATH := justfile_directory() / "app/.cache/gopath"
export CGO_ENABLED := "1"

# Run the native desktop app for the host platform.
[windows]
dev:
    go run ./cmd/ipa-loader

[macos]
dev:
    go run ./cmd/ipa-loader

[linux]
dev:
    sh scripts/dev-linux.sh

# Build a platform, the current platform by default, or every supported host target.
[windows]
release platform="":
    go run ./cmd/release {{quote(platform)}}

[macos]
release platform="":
    sh scripts/release.sh {{quote(platform)}}

[linux]
release platform="":
    sh scripts/release.sh {{quote(platform)}}

# Build the device payload used by the desktop's Install IPA Loader action.
[macos]
ios:
    sh scripts/build-ios.sh
