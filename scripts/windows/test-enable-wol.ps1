$ErrorActionPreference = 'Stop'
$wakeFixture = @{
    Armed = $false
    Magic = 'Disabled'
    Pattern = 'Enabled'
    FastStartup = 1
    Writes = 0
}

function Get-NetAdapter([switch]$Physical) {
    [pscustomobject]@{
        Name = 'Ethernet'
        InterfaceType = 6
        InterfaceDescription = 'Example Ethernet adapter'
        Status = 'Up'
    }
}

function Get-NetAdapterPowerManagement([string]$InterfaceDescription) {
    [pscustomobject]@{
        WakeOnMagicPacket = $wakeFixture.Magic
        WakeOnPattern = $wakeFixture.Pattern
    }
}

function Get-ItemProperty([string]$LiteralPath) {
    [pscustomobject]@{ HiberbootEnabled = $wakeFixture.FastStartup }
}

function Set-ItemProperty([string]$LiteralPath, [string]$Name, [int]$Value) {
    $wakeFixture.Writes++
    $wakeFixture.FastStartup = $Value
}

function Set-NetAdapterPowerManagement(
    [string]$Name, [switch]$NoRestart, [string]$WakeOnMagicPacket, [string]$WakeOnPattern
) {
    $wakeFixture.Writes++
    if ($WakeOnMagicPacket) { $wakeFixture.Magic = $WakeOnMagicPacket }
    if ($WakeOnPattern) { $wakeFixture.Pattern = $WakeOnPattern }
}

function powercfg.exe {
    $global:LASTEXITCODE = 0
    switch ($args[0]) {
        '/devicequery' {
            if ($args[1] -eq 'wake_programmable' -or $wakeFixture.Armed) {
                'Example Ethernet adapter'
            }
        }
        '/a' { 'Standby (S3)' }
        '/deviceenablewake' {
            $wakeFixture.Writes++
            $wakeFixture.Armed = $true
        }
        default { throw 'Unexpected powercfg operation.' }
    }
}

$scriptPath = Join-Path $PSScriptRoot 'enable-wol.ps1'
& $scriptPath
if ($wakeFixture.Writes -ne 0) { throw 'Read-only mode changed the fixture.' }

& $scriptPath -InterfaceName Ethernet -Apply -DisableFastStartup -WhatIf
if ($wakeFixture.Writes -ne 0) { throw 'WhatIf changed the fixture.' }

& $scriptPath -InterfaceName Ethernet -Apply -DisableFastStartup
if ($wakeFixture.Writes -ne 3 -or !$wakeFixture.Armed -or $wakeFixture.Magic -ne 'Enabled' -or
    $wakeFixture.Pattern -ne 'Disabled' -or $wakeFixture.FastStartup -ne 0) {
    throw 'Apply failed to change the expected settings.'
}

& $scriptPath -InterfaceName Ethernet -Apply -DisableFastStartup
if ($wakeFixture.Writes -ne 3) { throw 'Repeated Apply changed the fixture again.' }

Write-Host 'PASS Wake-on-LAN script read-only, WhatIf, Apply and repeat Apply behavior.'
