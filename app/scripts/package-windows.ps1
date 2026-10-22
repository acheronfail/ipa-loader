param([string]$Zig, [string]$Linker)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Use PowerShell 7 (pwsh) for Windows packaging.' }
if (-not $IsWindows) { throw 'Build the Windows release on Windows.' }
$appRoot = Split-Path $PSScriptRoot -Parent
$releaseRoot = Join-Path $appRoot 'build/release'
foreach ($parent in @((Join-Path $appRoot 'build'), $releaseRoot)) {
    if ((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Release output parents must not be links.' }
}
New-Item -ItemType Directory -Force $releaseRoot | Out-Null
$stage = Join-Path $releaseRoot ('.stage-' + [guid]::NewGuid().ToString('N'))
$packageName = 'IPA-Loader-windows-amd64'
$package = Join-Path $releaseRoot $packageName
$archive = Join-Path $releaseRoot ($packageName + '.zip')
$runningPackage = @(Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith($package + '\', [StringComparison]::OrdinalIgnoreCase) })
if ($runningPackage.Count) { throw 'Close the running packaged IPA Loader before replacing its release folder.' }
$backup = $null
$previousCGO = $env:CGO_ENABLED
$previousZig = $env:ZIG
if ($Zig) { $env:ZIG = $Zig }
New-Item -ItemType Directory $stage | Out-Null

# Every recursive cleanup/move target must be a resolved child of this release
# directory. Never follow links or copy a general development build directory.
function Assert-ReleaseChild([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($releaseRoot).TrimEnd('\') + '\'
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Release path escaped its output directory.' }
    if ((Test-Path -LiteralPath $full) -and ((Get-Item -LiteralPath $full).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Release paths must not be links.' }
}
function Remove-ReleaseTree([string]$Path) {
    Assert-ReleaseChild $Path
    # Windows scanners can briefly hold newly published headers/binaries open.
    # Retry only this generated tree; report persistent failures normally.
    for ($attemptIndex = 0; $attemptIndex -lt 6; $attemptIndex++) {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        try { Remove-Item -LiteralPath $Path -Recurse -Force; return }
        catch {
            if ($attemptIndex -eq 5) { throw }
            Start-Sleep -Milliseconds (250 * ($attemptIndex + 1))
        }
    }
}
function Copy-Runtime([string]$Name, [string[]]$Members) {
    $source = Join-Path $appRoot "build/$Name"
    $destination = Join-Path $stage $Name
    New-Item -ItemType Directory $destination | Out-Null
    foreach ($member in $Members) {
        $path = Join-Path $source $member
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing runtime input: $Name/$member" }
        $items = @((Get-Item -LiteralPath $path))
        if ($items[0].PSIsContainer) { $items += @(Get-ChildItem -LiteralPath $path -Recurse -Force) }
        if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Runtime inputs must not contain links.' }
        Copy-Item -LiteralPath $path -Destination $destination -Recurse
    }
}

try {
    $sharingArgs = @{}
    if ($Zig) { $sharingArgs.Zig = $Zig }
    if ($Linker) { $sharingArgs.Linker = $Linker }
    & (Join-Path $PSScriptRoot 'build-sharing-windows.ps1') @sharingArgs
    $env:CGO_ENABLED = '0'
    Copy-Runtime 'ios' @('IPA-Loader-Free-Accounts.ipa', 'IPA-Loader-Paid-Accounts.ipa')
    Copy-Runtime 'sharing-windows' @('IPALoaderSharingCompat-v1.dylib', 'manifest.json', 'LICENSE.fishhook', 'sources')
    Push-Location $appRoot
    try {
        & go run ./cmd/licenses (Join-Path $stage 'licenses')
        if ($LASTEXITCODE -ne 0) { throw 'Dependency notice collection failed.' }
        & go run ./cmd/embed-runtime internal/runtimebundle/payload.zip (Join-Path $stage 'sharing-windows') (Join-Path $stage 'licenses') (Join-Path $stage 'ios')
        if ($LASTEXITCODE -ne 0) { throw 'Runtime embedding failed.' }
        $buildArgs = @{ OutputDir = $stage; Bundled = $true }
        if ($Zig) { $buildArgs.Zig = $Zig }
        & (Join-Path $PSScriptRoot 'build-windows.ps1') @buildArgs
        & go run ./cmd/package-check -root $stage
        if ($LASTEXITCODE -ne 0) { throw 'Windows package dependency/integrity check failed.' }
    } finally { Pop-Location }
    @'
IPA Loader for Windows x64

Run the single release .exe. Helpers, licenses and sources are embedded and
extracted into the private user cache; no adjacent files are required. Launching from a
shortcut or another working directory is supported. No Go, Python or compiler
is needed to run this package.

Requires Windows 10/11 x64, OpenGL-capable graphics drivers, and Apple's desktop
iTunes/mobile-device support installed on the PC. Unlock and trust
the iPhone using Apple's device app before installing.

Authentication, signing and CMS verification run in Go. Account sessions and
signing keys are protected by current-user DPAPI under LocalAppData/ipa-loader.

Third-party licenses, sharing sources and build recipes are included.
release-manifest.json records file hashes and PE imports. This is an unsigned
local release.
'@ | Set-Content -LiteralPath (Join-Path $stage 'README.txt') -Encoding utf8
    # Record README as well as binaries, sources and notices in the final inventory.
    Push-Location $appRoot
    try {
        & go run ./cmd/package-check -root $stage -write-manifest
        if ($LASTEXITCODE -ne 0) { throw 'Release manifest generation failed.' }
    } finally { Pop-Location }
    Assert-ReleaseChild $package
    if (Test-Path -LiteralPath $package) {
        if (-not (Test-Path -LiteralPath (Join-Path $package 'release-manifest.json'))) { throw 'Existing release directory is not a generated package; preserve it before building here.' }
        $backup = Join-Path $releaseRoot ('.previous-' + [guid]::NewGuid().ToString('N'))
        Assert-ReleaseChild $backup
        Move-Item -LiteralPath $package -Destination $backup
    }
    Assert-ReleaseChild $stage
    Move-Item -LiteralPath $stage -Destination $package
    # Build a new ZIP before replacing the old archive.
    $temporaryZip = Join-Path $releaseRoot ('.archive-' + [guid]::NewGuid().ToString('N') + '.zip')
    Compress-Archive -LiteralPath $package -DestinationPath $temporaryZip -CompressionLevel Optimal
    Assert-ReleaseChild $archive
    Move-Item -LiteralPath $temporaryZip -Destination $archive -Force
    if ($backup) { Remove-ReleaseTree $backup }
    $single = Join-Path $releaseRoot ($packageName + '.exe')
    Copy-Item -LiteralPath (Join-Path $package 'ipa-loader.exe') -Destination $single -Force
    Write-Output "Single-file release: $single"
    Write-Output "Release folder: $package"
    Write-Output "Release archive: $archive"
} finally {
    $env:CGO_ENABLED = $previousCGO
    $env:ZIG = $previousZig
    if (Test-Path -LiteralPath $stage) { Remove-ReleaseTree $stage }
}
