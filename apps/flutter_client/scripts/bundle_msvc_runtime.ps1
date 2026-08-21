param(
    [Parameter(Mandatory = $true)]
    [string]$DestinationDirectory
)

$ErrorActionPreference = "Stop"

# Flutter's Windows runner and the Rust daemon are built with the MSVC
# toolchain. Keep the app self-contained so a clean Windows installation does
# not fail before the daemon can write a diagnostic log.
$destination = [System.IO.Path]::GetFullPath($DestinationDirectory)
New-Item -ItemType Directory -Force -Path $destination | Out-Null

$programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
$vswhereCandidates = @(
    (Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"),
    (Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe")
)
$vswhere = $vswhereCandidates |
    Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
    Select-Object -First 1

$redistRoots = @()
if ($vswhere) {
    $installations = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    foreach ($installation in $installations) {
        if ($installation) {
            $redistRoots += Join-Path $installation "VC\Redist\MSVC"
        }
    }
}

$crtDirectories = @()
foreach ($root in $redistRoots) {
    if (Test-Path -LiteralPath $root) {
        $crtDirectories += Get-ChildItem -LiteralPath $root -Directory -Recurse |
            Where-Object {
                $_.Name -match '^Microsoft\.VC\d+\.CRT$' -and
                $_.FullName -match '\\x64\\'
            }
    }
}

$crtDirectory = $crtDirectories |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $crtDirectory) {
    throw "Could not locate the x64 MSVC runtime in the Visual Studio installation."
}

$runtimeDlls = Get-ChildItem -LiteralPath $crtDirectory.FullName -Filter "*.dll" -File
if (-not $runtimeDlls) {
    throw "The MSVC runtime directory is empty: $($crtDirectory.FullName)"
}
foreach ($dll in $runtimeDlls) {
    Copy-Item -LiteralPath $dll.FullName -Destination $destination -Force
}

$required = @(
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll"
)
$missing = $required |
    Where-Object { -not (Test-Path -LiteralPath (Join-Path $destination $_)) }
if ($missing) {
    throw "The Windows bundle is missing MSVC runtime file(s): $($missing -join ', ')"
}

Write-Host "Bundled x64 MSVC runtime from $($crtDirectory.FullName) into $destination."
