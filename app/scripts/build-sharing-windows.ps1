param([string]$Zig, [string]$Linker)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Run this build on Windows.' }
$appRoot = Split-Path $PSScriptRoot -Parent
$compatRoot = Join-Path $appRoot 'internal/platform/compat'
$cache = Join-Path $appRoot '.cache/sharing-windows'
$output = Join-Path $appRoot 'build/sharing-windows'
New-Item -ItemType Directory -Force $cache, $output | Out-Null
if (-not $Zig) {
    $candidate = Get-Command zig -CommandType Application -ErrorAction SilentlyContinue
    if ($candidate) { $Zig = $candidate.Source }
}
if (-not $Zig) { throw 'Pass -Zig with the installed Zig executable.' }
# Zig 0.16 prints ZON, older releases print JSON. Read only the actual compiler
# path rather than assuming a Scoop shim lives beside the bundled headers.
$zigEnvironment = (& $Zig env) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Could not query Zig installation.' }
$libMatch = [regex]::Match($zigEnvironment, '(?:\.lib_dir|"lib_dir")\s*(?:=|:)\s*("(?:\\.|[^"\\])*")')
$exeMatch = [regex]::Match($zigEnvironment, '(?:\.zig_exe|"zig_exe")\s*(?:=|:)\s*("(?:\\.|[^"\\])*")')
if (-not $libMatch.Success -or -not $exeMatch.Success) { throw 'Unsupported Zig environment output.' }
$zigLib = $libMatch.Groups[1].Value | ConvertFrom-Json
$actualZig = $exeMatch.Groups[1].Value | ConvertFrom-Json
$darwin = Join-Path $zigLib 'libc/include/any-darwin-any'
if (-not (Test-Path -LiteralPath (Join-Path $darwin 'objc/NSObject.h'))) { throw 'Zig Darwin public headers are missing.' }
if (-not $Linker) {
    $rustRoot = Join-Path $env:USERPROFILE '.rustup/toolchains'
    $stable = Join-Path $rustRoot 'stable-x86_64-pc-windows-msvc/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe'
    if (Test-Path -LiteralPath $stable) { $Linker = $stable }
    elseif (Test-Path -LiteralPath $rustRoot) {
        $candidate = Get-ChildItem -LiteralPath $rustRoot -Directory | Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName 'lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe' } |
            Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if ($candidate) { $Linker = $candidate }
    }
}
if (-not $Linker) { throw 'Pass -Linker with LLVM ld64.lld or rust-lld (Darwin flavor).' }
$linkerPrefix = @()
if ([IO.Path]::GetFileNameWithoutExtension($Linker) -eq 'rust-lld') { $linkerPrefix = @('-flavor', 'darwin') }
$zigVersion = (& $actualZig version) -join "`n"
$linkerVersion = (& $Linker @linkerPrefix --version) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'The installed linker does not support Darwin Mach-O.' }

$headers = Join-Path $compatRoot 'windows'
$stubs = Join-Path $headers 'stubs'
$libraryName = 'IPALoaderSharingCompat-v1.dylib'
$common = @('cc', '-target', 'aarch64-ios.12.0', '-isystem', $darwin, '-fno-sanitize=all', '-O2', '-g0')
foreach ($source in @('sharing.m', 'fishhook.c')) {
    $object = Join-Path $cache ($source + '.o')
    $arguments = $common + @('-I', $headers)
    if ($source -eq 'sharing.m') { $arguments += '-fobjc-arc' }
    $arguments += @('-c', (Join-Path $compatRoot $source), '-o', $object)
    & $actualZig @arguments *> (Join-Path $cache ($source + '.log'))
    if ($LASTEXITCODE -ne 0) { throw "Sharing compile failed; inspect $cache/$source.log" }
}
$arguments = $linkerPrefix + @('-dylib', '-arch', 'arm64', '-platform_version', 'ios', '12.0', '12.0',
    '-install_name', "@rpath/$libraryName", '-no_adhoc_codesign', "-L$stubs", "-F$stubs",
    '-lSystem', '-lobjc', '-framework', 'Foundation', '-framework', 'CoreFoundation', '-framework', 'Security',
    (Join-Path $cache 'sharing.m.o'), (Join-Path $cache 'fishhook.c.o'), '-o', (Join-Path $output $libraryName))
& $Linker @arguments *> (Join-Path $cache 'link.log')
if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath (Join-Path $output $libraryName)).Length -eq 0) { throw "Sharing link failed; inspect $cache/link.log" }

$sourceHashes = [ordered]@{}
$inputs = @('sharing.m', 'fishhook.c', 'fishhook.h', 'LICENSE.fishhook') + @(
    Get-ChildItem -LiteralPath $headers -Recurse -File | ForEach-Object {
        [IO.Path]::GetRelativePath($compatRoot, $_.FullName).Replace('\', '/')
    }
)
foreach ($relative in $inputs) {
    $inputFile = Join-Path $compatRoot $relative
    $relativeKey = "compat/$relative"
    $destination = Join-Path $output "sources/$relativeKey"
    New-Item -ItemType Directory -Force (Split-Path $destination -Parent) | Out-Null
    Copy-Item -LiteralPath $inputFile -Destination $destination -Force
    $sourceHashes[$relativeKey] = (Get-FileHash -LiteralPath $inputFile -Algorithm SHA256).Hash.ToLowerInvariant()
}
$recipe = $PSCommandPath
Copy-Item -LiteralPath $recipe -Destination (Join-Path $output 'sources/build-sharing-windows.ps1') -Force
Copy-Item -LiteralPath (Join-Path $compatRoot 'LICENSE.fishhook') -Destination (Join-Path $output 'LICENSE.fishhook') -Force
$manifest = [ordered]@{
    format = 1
    target = 'arm64-ios12.0'
    library = $libraryName
    library_sha256 = (Get-FileHash -LiteralPath (Join-Path $output $libraryName) -Algorithm SHA256).Hash.ToLowerInvariant()
    compiler = @{ version = $zigVersion; sha256 = (Get-FileHash -LiteralPath $actualZig -Algorithm SHA256).Hash.ToLowerInvariant() }
    linker = @{ version = $linkerVersion; sha256 = (Get-FileHash -LiteralPath $Linker -Algorithm SHA256).Hash.ToLowerInvariant() }
    recipe_sha256 = (Get-FileHash -LiteralPath $recipe -Algorithm SHA256).Hash.ToLowerInvariant()
    sources = $sourceHashes
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding utf8
Write-Output "Built $output/$libraryName"
