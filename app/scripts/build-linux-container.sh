#!/bin/sh
# Build Linux amd64 on macOS using an isolated Linux toolchain, not macOS SDKs.
set -eu
app_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if ! command -v docker >/dev/null 2>&1; then
  echo 'Linux releases on macOS require Docker with Linux containers enabled.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo 'Start the Docker Linux engine before building a Linux release.' >&2
  exit 1
fi
image=ipa-loader-linux-release:go1.26.2-zig0.16
# Build on amd64 even on Apple Silicon: the current pinned keyring helper is amd64.
docker build --platform linux/amd64 -f "$app_root/scripts/Dockerfile.linux-release" -t "$image" "$app_root/scripts"
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$app_root,target=/src/app" --workdir /src/app \
  "$image" sh scripts/build-linux.sh
