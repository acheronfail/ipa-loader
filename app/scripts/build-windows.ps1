param([string]$Zig, [switch]$HeadlessTests, [switch]$BuildSharing, [string]$OutputDir, [switch]$Bundled)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Run this build on Windows.' }
if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') { throw 'This recipe currently supports Windows x64.' }
$appRoot = Split-Path $PSScriptRoot -Parent
$output = if ($OutputDir) { [IO.Path]::GetFullPath($OutputDir) } else { Join-Path $appRoot 'build' }
New-Item -ItemType Directory -Force $output | Out-Null
if (-not $Zig) {
    $command = Get-Command zig -CommandType Application -ErrorAction SilentlyContinue
    if ($command) { $Zig = $command.Source }
}
if (-not $Zig) { throw 'Install Zig, or provide its absolute executable path with -Zig.' }
if ($BuildSharing) {
    & (Join-Path $PSScriptRoot 'build-sharing-windows.ps1') -Zig $Zig
}
$variables = @('GOMODCACHE', 'GOCACHE', 'GOPATH', 'CGO_ENABLED', 'CC', 'CXX')
$previous = @{}
foreach ($name in $variables) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location $appRoot
try {
    $env:GOMODCACHE = Join-Path $appRoot '.cache/gomod'
    $env:GOCACHE = Join-Path $appRoot '.cache/build'
    $env:GOPATH = Join-Path $appRoot '.cache/gopath'
    $env:CGO_ENABLED = '1'
    $compiler = $Zig.Replace('\', '/')
    $env:CC = '"' + $compiler + '" cc'
    $env:CXX = '"' + $compiler + '" c++'
    if ($HeadlessTests) {
        & go test -count=1 -tags ci ./cmd/... ./internal/...
        if ($LASTEXITCODE -ne 0) { throw 'Windows native tests failed.' }
    }
    & go run ./cmd/windows-resources cmd/ipa-loader/rsrc_windows_amd64.syso
    if ($LASTEXITCODE -ne 0) { throw 'Windows icon resource generation failed.' }
    # Zig's external linker needs an explicit subsystem in addition to Go's flag.
    $goBuildArgs = @('build', '-trimpath', '-ldflags', '-H=windowsgui -extldflags=-Wl,--subsystem,windows', '-o', (Join-Path $output 'ipa-loader.exe'))
    if ($Bundled) { $goBuildArgs += @('-tags', 'bundled') }
    $goBuildArgs += './cmd/ipa-loader'
    & go @goBuildArgs
    if ($LASTEXITCODE -ne 0) { throw 'Windows desktop build failed.' }
    Write-Output "Built $output/ipa-loader.exe with pure-Go authentication. Device installation acceptance is separate."
} finally {
    Pop-Location
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') }
}
