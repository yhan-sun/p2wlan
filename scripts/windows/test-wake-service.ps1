[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CliPath,
    [Parameter(Mandatory)][string]$DaemonPath,
    [Parameter(Mandatory)][string]$WintunPath
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$app = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'P2WLAN'
$machine = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'p2wlan'
$sourceDir = Join-Path ([System.IO.Path]::GetTempPath()) ('p2wlan-service-test-' + [guid]::NewGuid().ToString('N'))
$cli = (Resolve-Path -LiteralPath $CliPath).Path
$daemon = (Resolve-Path -LiteralPath $DaemonPath).Path
$wintun = (Resolve-Path -LiteralPath $WintunPath).Path
if ((Test-Path -LiteralPath $app) -or (Test-Path -LiteralPath $machine) -or (Get-Service -Name P2WLAN -ErrorAction SilentlyContinue)) {
    throw 'The service test requires a disposable Windows host without an existing P2WLAN installation.'
}

function Assert-PrivatePermissions([string]$Path) {
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $allow = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
        Where-Object AccessControlType -EQ 'Allow' |
        ForEach-Object { $_.IdentityReference.Value } |
        Sort-Object -Unique)
    if ($owner -notin $trusted -or (Compare-Object $trusted $allow)) {
        throw 'The machine profile has unexpected ownership or grants.'
    }
}

try {
    New-Item -ItemType Directory -Path $app, $sourceDir | Out-Null
    Copy-Item -LiteralPath $daemon -Destination (Join-Path $app 'p2wlan-daemon.exe')
    Copy-Item -LiteralPath $wintun -Destination (Join-Path $app 'wintun.dll')
    # Model an installed, administrator-owned package on hosted runners.
    & icacls.exe $app /setowner '*S-1-5-32-544' /T /Q | Out-Null

    $config = Join-Path $sourceDir 'p2wlan-config.json'
    $initDaemon = Join-Path $app 'p2wlan-daemon.exe'
    $init = Start-Process -FilePath $initDaemon -ArgumentList @('--init', '--config', ('"' + $config + '"'), '--control', 'https://127.0.0.1:1') -PassThru
    if (-not $init.WaitForExit(10000)) {
        $init.Kill()
        throw 'Generated service-test profile timed out.'
    }
    if ($init.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $config)) { throw 'Failed to generate service-test profile.' }
    $source = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
    $source.control.device_credential = 'synthetic-local-service-test'
    $source.control.credential_issued = $true
    $source.control.auth_token = 'synthetic-user-token-must-not-migrate'
    $source | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $config -Encoding utf8NoBOM
    @{ version = 1; incarnation = 123; last_boot_epoch_ms = 123 } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $sourceDir 'incarnation.json') -Encoding utf8NoBOM

    foreach ($attempt in 1..2) {
        & $cli --config $config service install --migrate-identity | Out-Null
        $status = & $cli service status --json | ConvertFrom-Json
        if (-not $status.installed -or $status.profile -ne 'personal' -or $status.state -ne 'running') {
            throw "Installation attempt $attempt did not produce the product service."
        }
    }
    $registered = Get-CimInstance Win32_Service -Filter "Name='P2WLAN'"
    if ($registered.StartName -ne 'LocalSystem' -or $registered.StartMode -ne 'Auto') {
        throw 'SCM must run the product service as LocalSystem on startup.'
    }
    $migratedPath = Join-Path $machine 'p2wlan-config.json'
    Assert-PrivatePermissions $machine
    Assert-PrivatePermissions $migratedPath
    $migrated = Get-Content -LiteralPath $migratedPath -Raw | ConvertFrom-Json
    if ($migrated.control.auth_token -or $migrated.node.public_key -ne $source.node.public_key -or
        $migrated.control.device_credential -ne $source.control.device_credential) {
        throw 'The protected profile did not retain exactly the enrolled device identity.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $counterPath = Join-Path $machine 'incarnation.json'
        $counter = Get-Content -LiteralPath $counterPath -Raw | ConvertFrom-Json
        if ($counter.incarnation -gt 123) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($counter.incarnation -le 123) { throw 'The service did not advance the migrated registration counter.' }
    Assert-PrivatePermissions $counterPath
    foreach ($attempt in 1..2) {
        & $cli service uninstall | Out-Null
        $status = & $cli service status --json | ConvertFrom-Json
        if ($status.installed -or $status.state -ne 'not_installed') {
            throw "Uninstall attempt $attempt left a registered service."
        }
    }
    if (-not (Test-Path -LiteralPath $migratedPath) -or -not (Test-Path -LiteralPath $config)) {
        throw 'Uninstall must retain the machine and original profiles.'
    }

    & $cli --config $migratedPath config set wake-allow-remote true | Out-Null
    $source.control.device_credential = 'synthetic-rotated-service-test'
    $source | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $config -Encoding utf8NoBOM
    & $cli --config $config service install --migrate-identity | Out-Null
    $refreshed = Get-Content -LiteralPath $migratedPath -Raw | ConvertFrom-Json
    if (-not $refreshed.wake.allow_remote -or $refreshed.control.auth_token -or
        $refreshed.control.device_credential -ne $source.control.device_credential) {
        throw 'Credential renewal did not retain the existing private machine settings.'
    }
    Assert-PrivatePermissions $migratedPath
    Write-Host 'Boot-time service install, private state, repeat uninstall and credential migration verified.'
} finally {
    if (Get-Service -Name P2WLAN -ErrorAction SilentlyContinue) {
        & $cli service uninstall | Out-Null
    }
    foreach ($path in @($app, $machine, $sourceDir)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
}
