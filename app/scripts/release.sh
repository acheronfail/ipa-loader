#!/bin/sh
set -eu
app_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$app_root"
export GOMODCACHE="$app_root/.cache/gomod" GOCACHE="$app_root/.cache/build" GOPATH="$app_root/.cache/gopath"
exec go run ./cmd/release "$@"
