#!/bin/sh
# Run the Linux app with its source-built sharing runtime.
set -eu
app_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$app_root"
export GOMODCACHE="$app_root/.cache/gomod"
export GOCACHE="$app_root/.cache/build"
export GOPATH="$app_root/.cache/gopath"
export CGO_ENABLED=1
export IPA_LOADER_LINUX_RUNTIME="${IPA_LOADER_LINUX_RUNTIME:-$app_root/build}"
if [ ! -f "$IPA_LOADER_LINUX_RUNTIME/sharing-linux/manifest.json" ]; then
  echo 'Build the Linux runtime first: sh app/scripts/build-linux.sh (from the repository root).' >&2
  exit 1
fi
exec go run ./cmd/ipa-loader
