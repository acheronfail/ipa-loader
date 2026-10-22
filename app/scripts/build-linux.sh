#!/bin/sh
# Linux desktop package. Native dependencies remain supplied by the distribution.
set -eu
app_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$app_root"
if [ "$(uname -s)" != Linux ]; then
  echo 'Run this builder on Linux.' >&2
  exit 1
fi
export GOMODCACHE="$app_root/.cache/gomod"
export GOCACHE="$app_root/.cache/build"
export GOPATH="$app_root/.cache/gopath"
export CGO_ENABLED=1
python3 scripts/build-sharing-linux.py
python3 scripts/build-keyring-linux.py
arch=$(go env GOARCH)
bundle="$app_root/build/release/IPA-Loader-linux-$arch"
mkdir -p "$bundle"
go run ./cmd/licenses "$bundle/licenses"
# Copy complete, freshly checked runtime trees, not stale release members.
rm -rf "$bundle/signing-linux" "$bundle/sharing-linux" "$bundle/keyring-linux"
cp -R build/sharing-linux build/keyring-linux "$bundle/"
# Bootstrap payloads are built on macOS and supplied to this host build.
if [ ! -f build/ios/IPA-Loader.ipa ] || [ ! -f build/ios/IPA-Loader-VPN.ipa ]; then
  echo 'Missing build/ios/IPA-Loader.ipa. Build with just ios on macOS and copy it here.' >&2
  exit 1
fi
mkdir -p "$bundle/ios"
cp build/ios/IPA-Loader*.ipa "$bundle/ios/"
# Embed helpers, corresponding sources and all dependency notices in the binary.
go run ./cmd/embed-runtime internal/runtimebundle/payload.zip "$bundle/sharing-linux" "$bundle/keyring-linux" "$bundle/licenses" "$bundle/ios"
go build -tags bundled -trimpath -ldflags '-s -w' -o "$bundle/ipa-loader" ./cmd/ipa-loader
cat > "$bundle/README.txt" <<'TEXT'
Run ./ipa-loader from your desktop session. Linux runtime dependencies include
OpenGL/EGL, X11/Wayland, libsecret/GLib and a desktop Secret Service.
The secret-tool helper is embedded alongside its license and matching source.
A running usbmuxd and a paired, unlocked USB iPhone are required for installation.
Use idevicepair pair and accept Trust on the phone to establish initial pairing.
Signing and CMS verification run in Go. No zsign, OpenSSL or Apple host libraries
are included. The executable embeds the sharing adapter, keyring helper and
licenses, extracted to the private user cache. Host graphics, libc, libsecret,
Secret Service and usbmuxd remain system prerequisites.
TEXT
cat > "$bundle/run-ipa-loader" <<'LAUNCH'
#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$here/ipa-loader" "$@"
LAUNCH
chmod 755 "$bundle/run-ipa-loader"
go run ./cmd/package-check --root "$bundle" --write-manifest
tar -C "$(dirname "$bundle")" -czf "$bundle.tar.gz" "$(basename "$bundle")"
printf 'Built: %s\n' "$bundle"

# Publish a copyable executable as the primary release; the folder remains an audit artifact.
cp "$bundle/ipa-loader" "$bundle.bin.tmp"
chmod 755 "$bundle.bin.tmp"
mv "$bundle.bin.tmp" "$bundle.bin"
printf 'Single-file release: %s\n' "$bundle.bin"
