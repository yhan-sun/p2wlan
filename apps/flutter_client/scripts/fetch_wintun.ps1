param(
    [Parameter(Mandatory = $true)]
    [string]$DestinationDirectory,

    [ValidateSet("amd64", "x86", "arm64", "arm")]
    [string]$Architecture = "amd64"
)

$ErrorActionPreference = "Stop"

# Wintun is distributed as a signed, pre-built DLL. Keep the source pinned so
# every local and CI package contains the same runtime and is verified before
# it is copied next to p2wlan-daemon.exe.
$wintunVersion = "0.14.1"
$downloadUrl = "https://www.wintun.net/builds/wintun-$wintunVersion.zip"
$expectedSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

$destination = [System.IO.Path]::GetFullPath($DestinationDirectory)
$tempRoot = if ($env:RUNNER_TEMP) {
    Join-Path $env:RUNNER_TEMP "p2wlan-wintun"
} else {
    Join-Path ([System.IO.Path]::GetTempPath()) "p2wlan-wintun"
}
$archivePath = Join-Path $tempRoot "wintun-$wintunVersion.zip"
$extractRoot = Join-Path $tempRoot "extract"

New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
New-Item -ItemType Directory -Force -Path $destination | Out-Null

if (Test-Path -LiteralPath $archivePath) {
    $cachedHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($cachedHash -ne $expectedSha256) {
        Remove-Item -LiteralPath $archivePath -Force
    }
}

if (-not (Test-Path -LiteralPath $archivePath)) {
    Write-Host "Downloading Wintun $wintunVersion..."
    Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $archivePath
}

$actualSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    throw "Wintun archive SHA-256 mismatch. Expected $expectedSha256, got $actualSha256."
}

if (Test-Path -LiteralPath $extractRoot) {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force
}
Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot -Force

$dllPath = Join-Path $extractRoot "wintun\bin\$Architecture\wintun.dll"
if (-not (Test-Path -LiteralPath $dllPath)) {
    throw "Wintun DLL was not found in the verified archive: $dllPath"
}

Copy-Item -LiteralPath $dllPath -Destination (Join-Path $destination "wintun.dll") -Force

# Keep the redistributable notice beside the DLL when the archive provides it.
$licenseCandidates = @(
    (Join-Path $extractRoot "wintun\prebuilt-binaries-license.txt"),
    (Join-Path $extractRoot "wintun\LICENSE.txt"),
    (Join-Path $extractRoot "wintun\LICENSE")
)
$license = $licenseCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($license) {
    Copy-Item -LiteralPath $license -Destination (Join-Path $destination "wintun-license.txt") -Force
}

Write-Host "Bundled verified Wintun $wintunVersion ($Architecture) at $(Join-Path $destination 'wintun.dll')."
