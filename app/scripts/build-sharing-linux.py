#!/usr/bin/env python3
"""Cross-build the existing iOS sharing adapter on Linux using Zig and ld64.lld.

Zig supplies public Darwin C/Objective-C headers. The repository's reviewed
framework declarations and .tbd stubs provide the SDK boundary. No Apple SDK or
Apple host libraries are linked or copied into the Linux application.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COMPAT = ROOT / 'internal/platform/compat'
CACHE = ROOT / '.cache/sharing-linux'
OUT = ROOT / 'build/sharing-linux'
NAME = 'IPALoaderSharingCompat-v1.dylib'

def digest(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', default=shutil.which('zig') or str(ROOT / '.cache/toolchains/zig/zig'))
    parser.add_argument('--linker', default=shutil.which('ld64.lld') or shutil.which('ld64.lld-21'))
    args = parser.parse_args()
    if not args.zig or not args.linker:
        parser.error('Supply --zig and --linker with Zig and LLVM ld64.lld executable paths')
    zig = Path(args.zig).resolve()
    linker = Path(args.linker).resolve()
    linker_prefix = ['-flavor', 'darwin'] if linker.name in ('lld', 'rust-lld') else []
    zig_environment = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(ROOT / '.cache/zig-global'), ZIG_LOCAL_CACHE_DIR=str(CACHE / 'zig-cache'))
    environment = subprocess.check_output([str(zig), 'env'], text=True, env=zig_environment)
    match = re.search(r'(?:\.lib_dir|"lib_dir")\s*(?:=|:)\s*("(?:\\.|[^"\\])*")', environment)
    if not match:
        raise SystemExit('Unsupported Zig environment output')
    darwin = Path(json.loads(match.group(1))) / 'libc/include/any-darwin-any'
    if not (darwin / 'objc/NSObject.h').is_file():
        raise SystemExit('Zig Darwin public headers are missing')
    CACHE.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    headers = COMPAT / 'windows'
    for source in ['sharing.m', 'fishhook.c']:
        arguments = [str(zig), 'cc', '-target', 'aarch64-ios.12.0', '-isystem', str(darwin), '-fno-sanitize=all', '-O2', '-g0', '-I', str(headers)]
        if source.endswith('.m'):
            arguments += ['-fobjc-arc']
        arguments += ['-c', str(COMPAT / source), '-o', str(CACHE / (source+'.o'))]
        # Zig's cache is local to this project, including in restricted shells.
        environment = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(ROOT / '.cache/zig-global'), ZIG_LOCAL_CACHE_DIR=str(CACHE / 'zig-cache'))
        with (CACHE / (source+'.log')).open('wb') as log:
            subprocess.run(arguments, env=environment, check=True, stdout=log, stderr=subprocess.STDOUT)
    stubs = headers / 'stubs'
    command = [str(linker)] + linker_prefix + ['-dylib', '-arch', 'arm64', '-platform_version', 'ios', '12.0', '12.0', '-install_name', '@rpath/'+NAME, '-no_adhoc_codesign', '-L'+str(stubs), '-F'+str(stubs), '-lSystem', '-lobjc', '-framework', 'Foundation', '-framework', 'CoreFoundation', '-framework', 'Security', str(CACHE / 'sharing.m.o'), str(CACHE / 'fishhook.c.o'), '-o', str(OUT / NAME)]
    with (CACHE / 'link.log').open('wb') as log:
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
    inputs = [COMPAT / n for n in ['sharing.m','fishhook.c','fishhook.h','LICENSE.fishhook']] + sorted(p for p in headers.rglob('*') if p.is_file())
    sources = {}
    for source in inputs:
        relative = 'compat/'+source.relative_to(COMPAT).as_posix()
        destination = OUT / 'sources' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        sources[relative] = digest(source)
    recipe = Path(__file__).resolve()
    shutil.copy2(recipe, OUT / 'sources' / recipe.name)
    shutil.copy2(COMPAT / 'LICENSE.fishhook', OUT / 'LICENSE.fishhook')
    manifest = dict(format=1,target='arm64-ios12.0',library=NAME,library_sha256=digest(OUT / NAME),
                    compiler=dict(version=subprocess.check_output([str(zig),'version'],text=True,env=zig_environment).strip(),sha256=digest(zig)),
                    linker=dict(version=subprocess.check_output([str(linker)]+linker_prefix+['--version'],text=True).strip(),sha256=digest(linker)),
                    recipe_sha256=digest(recipe),sources=sources)
    (OUT / 'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'Built {OUT / NAME}')

if __name__ == '__main__':
    main()
