#!/usr/bin/env python3
"""Package the pinned Debian Secret Service CLI, notices and matching source.

No host installation is performed. The helper is dynamically linked to libsecret
and GLib supplied by the desktop distribution. Current recipe targets amd64.
"""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/keyring-linux'
OUT = ROOT / 'build/keyring-linux'
POOL = 'https://deb.debian.org/debian/pool/main/libs/libsecret/'
INPUTS = {
 'libsecret-tools_0.21.8.2-2_amd64.deb': '8bd313163dc6774380a83814b02ebf2c702084fa860b1814984079b3105f5456',
 'libsecret_0.21.8.2.orig.tar.xz': '142948339c5b971d8f6a8c7099521f6fd319b6fe73d2694b4e6d3310ed28b6e6',
 'libsecret_0.21.8.2-2.debian.tar.xz': '46b261bedb28c28b45bbfc61c8c37ab8573d41e3576fd6f0b74628f26146eb36',
}
def digest(path):
 with path.open('rb') as f:
  return hashlib.file_digest(f, 'sha256').hexdigest()
def main():
 if platform.system() != 'Linux' or platform.machine() != 'x86_64':
  raise SystemExit('The pinned keyring helper currently supports Linux amd64')
 CACHE.mkdir(parents=True, exist_ok=True)
 OUT.mkdir(parents=True, exist_ok=True)
 for name, expected in INPUTS.items():
  path = CACHE / name
  existing = ROOT / '.cache/linux-debs' / name
  if not path.exists() and existing.exists(): shutil.copy2(existing, path)
  if not path.exists(): urllib.request.urlretrieve(POOL + name, path)
  if digest(path) != expected: raise SystemExit('Keyring helper input hash mismatch: ' + name)
  if name.endswith('.deb'):
   unpacked = CACHE / 'unpacked'
   subprocess.run(['dpkg-deb', '-x', str(path), str(unpacked)], check=True)
   shutil.copy2(unpacked / 'usr/bin/secret-tool', OUT / 'secret-tool')
   shutil.copy2(unpacked / 'usr/share/doc/libsecret-tools/copyright', OUT / 'COPYRIGHT')
  else: shutil.copy2(path, OUT / name)
 shutil.copy2('/usr/share/common-licenses/LGPL-2.1', OUT / 'LICENSE.LGPL-2.1')
 shutil.copy2(Path(__file__), OUT / Path(__file__).name)
 (OUT / 'manifest.json').write_text(json.dumps({'format': 1, 'platform': 'linux/amd64', 'inputs': INPUTS, 'secret_tool_sha256': digest(OUT / 'secret-tool')}, indent=2) + '\n')
 print('Packaged pinned Secret Service helper, license and source')
if __name__ == '__main__': main()
