param(
    [Parameter(Mandatory=$true)][ValidateSet('control', 'relay')][string]$Role,
    [Parameter(Mandatory=$true)][string]$ConfigDirectory,
    [Parameter(Mandatory=$true)][string]$BinaryDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$config = (Resolve-Path -LiteralPath $ConfigDirectory).Path
$binary = Join-Path (Resolve-Path -LiteralPath $BinaryDirectory).Path "p2wlan-$Role.exe"
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Server binary not found' }
foreach ($line in [IO.File]::ReadAllLines((Join-Path $config "$Role.env"))) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) { continue }
    $parts = $line.Split(@('='), 2)
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[A-Z][A-Z0-9_]*$') { throw 'Invalid environment file entry' }
    [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
}
& $binary
exit $LASTEXITCODE
