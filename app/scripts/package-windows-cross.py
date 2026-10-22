#!/usr/bin/env python3
"""Cross-build Windows amd64 GUI and sharing runtime; signing is pure Go.

Requires Go, Zig, Python 3.12+ and a Darwin-capable LLVM linker. Target executables
are audited as PE data, never executed on the build host. No OpenSSL/zsign build.
"""
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/windows-cross'

def run(args,env,log=None):
    print('Running: '+shlex.join(map(str,args[:5]))+(' …' if len(args)>5 else ''),flush=True)
    if log:
        with Path(log).open('wb') as stream:
            p=subprocess.run(list(map(str,args)),cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT)
        if p.returncode: raise SystemExit(f'Build failed; inspect {log}')
    else: subprocess.run(list(map(str,args)),cwd=ROOT,env=env,check=True)

def main():
    if platform.system() not in ('Linux','Darwin'): raise SystemExit('Use package-windows.ps1 on Windows')
    zig=os.environ.get('ZIG') or shutil.which('zig') or str(ROOT/'.cache/toolchains/zig/zig')
    if not Path(zig).is_file(): raise SystemExit('Install Zig or set ZIG to its executable path')
    zig=str(Path(zig).resolve())
    if not shutil.which('go'): raise SystemExit('Go is required')
    CACHE.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ)
    for key in ('SDKROOT','MACOSX_DEPLOYMENT_TARGET','CFLAGS','CXXFLAGS','CPPFLAGS','LDFLAGS','CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','LIBRARY_PATH','PKG_CONFIG_PATH','PKG_CONFIG_SYSROOT_DIR','GOOS','GOARCH','CC','CXX','CGO_CFLAGS','CGO_CPPFLAGS','CGO_CXXFLAGS','CGO_LDFLAGS'): env.pop(key,None)
    env.update(ZIG_GLOBAL_CACHE_DIR=str(ROOT/'.cache/zig-global'),ZIG_LOCAL_CACHE_DIR=str(CACHE/'zig-cache'))
    for name,kind in [('cc','cc'),('cxx','c++')]:
        p=CACHE/name;p.write_text('#!/bin/sh\nexec '+shlex.join([zig,kind,'-target','x86_64-windows-gnu'])+' "$@"\n');p.chmod(0o755)
    env.update(CC=shlex.quote(str(CACHE/'cc')),CXX=shlex.quote(str(CACHE/'cxx')))
    args=['python3','scripts/build-sharing-linux.py','--zig',zig]
    if os.environ.get('LD64_LLD'):args+=['--linker',os.environ['LD64_LLD']]
    run(args,env)
    sharing=ROOT/'build/sharing-windows'
    if sharing.exists():shutil.rmtree(sharing)
    shutil.copytree(ROOT/'build/sharing-linux',sharing)
    manifest=json.loads((sharing/'manifest.json').read_text());manifest['recipe']='build-sharing-linux.py'
    (sharing/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    release=ROOT/'build/release';release.mkdir(exist_ok=True)
    stage=release/'IPA-Loader-windows-amd64-cross';stage.mkdir(exist_ok=True)
    # Remove old runtime trees from previous generated cross releases.
    for name in ('signing-windows','sharing-windows','licenses','ios'):
        p=stage/name
        if p.exists():shutil.rmtree(p)
    shutil.copytree(sharing,stage/'sharing-windows')
    ios=ROOT/'build/ios/IPA-Loader.ipa'
    if not ios.is_file(): raise SystemExit('Build just ios on macOS and supply build/ios/IPA-Loader.ipa before packaging')
    (stage/'ios').mkdir(exist_ok=True)
    shutil.copy2(ios,stage/'ios/IPA-Loader.ipa')
    vpn=ios.with_name('IPA-Loader-VPN.ipa')
    if not vpn.is_file(): raise SystemExit('Missing IPA-Loader-VPN.ipa')
    shutil.copy2(vpn,stage/'ios/IPA-Loader-VPN.ipa')
    host=dict(env,CGO_ENABLED='0',ZIG=zig)
    run(['go','run','./cmd/licenses',stage/'licenses'],host)
    run(['go','run','./cmd/embed-runtime','internal/runtimebundle/payload.zip',stage/'sharing-windows',stage/'licenses',stage/'ios'],host)
    target=dict(env,GOOS='windows',GOARCH='amd64',CGO_ENABLED='1')
    run(['go','build','-tags','bundled','-trimpath','-ldflags','-s -w -H=windowsgui','-o',stage/'ipa-loader.exe','./cmd/ipa-loader'],target,CACHE/'go-build.log')
    run(['go','run','./cmd/cross-package-check','-root',stage],host)
    output=release/'IPA-Loader-windows-amd64.exe';shutil.copy2(stage/'ipa-loader.exe',output)
    with zipfile.ZipFile(release/'IPA-Loader-windows-amd64-cross.zip','w',zipfile.ZIP_DEFLATED) as out:
        for p in sorted(stage.rglob('*')):
            if p.is_file():out.write(p,p.relative_to(release))
    print(f'Single-file Windows release: {output}',flush=True)
if __name__=='__main__':main()
