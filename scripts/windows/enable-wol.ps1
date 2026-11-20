# Print hardware and Windows settings before making any change.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InterfaceName,
    [switch]$Apply,
    [switch]$DisableFastStartup
)

$ErrorActionPreference = 'Stop'
$powerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'

function Invoke-WakePowerCfg {
    $output = @(& powercfg.exe @args)
    if ($LASTEXITCODE -ne 0) { throw "powercfg.exe failed with exit code $LASTEXITCODE." }
    return $output
}

if ($Apply -and -not $InterfaceName) { throw '-Apply requires an exact -InterfaceName.' }
if ($DisableFastStartup -and -not $Apply) { throw '-DisableFastStartup requires -Apply.' }

$adapters = @(Get-NetAdapter -Physical | Where-Object {
    [int]$_.InterfaceType -eq 6 -and (-not $InterfaceName -or $_.Name -eq $InterfaceName)
})
if ($adapters.Count -eq 0) { throw 'No matching physical Ethernet adapter was found.' }
if ($Apply -and $adapters.Count -ne 1) { throw '-InterfaceName must identify exactly one Ethernet adapter.' }

$armed = @(Invoke-WakePowerCfg /devicequery wake_armed)
$programmable = @(Invoke-WakePowerCfg /devicequery wake_programmable)
$sleepStates = @(Invoke-WakePowerCfg /a)
$fastStartup = (Get-ItemProperty -LiteralPath $powerKey).HiberbootEnabled

Write-Host "Fast startup (HiberbootEnabled): $fastStartup"
Write-Host 'Available sleep states:'
$sleepStates | Write-Host
Write-Host 'Wake-armed devices:'
$armed | Write-Host

foreach ($adapter in $adapters) {
    Write-Host "Ethernet: $($adapter.Name) ($($adapter.InterfaceDescription)), $($adapter.Status)"
    try {
        $settings = Get-NetAdapterPowerManagement -InterfaceDescription $adapter.InterfaceDescription
    } catch {
        if ($Apply) { throw }
        Write-Warning 'Adapter power settings could not be read. Retry in an elevated PowerShell session.'
        continue
    }
    Write-Host "WakeOnMagicPacket: $($settings.WakeOnMagicPacket); WakeOnPattern: $($settings.WakeOnPattern)"
    if (-not $Apply) { continue }

    if ($settings.WakeOnMagicPacket -notin @('Enabled', 'Disabled')) {
        throw 'The adapter driver does not report a configurable WakeOnMagicPacket option.'
    }
    if ($adapter.InterfaceDescription -notin $armed -and $adapter.InterfaceDescription -notin $programmable) {
        throw 'powercfg does not report this exact adapter description. Enable device wake in Device Manager first.'
    }
    if (@(Get-NetAdapter -Physical | Where-Object InterfaceDescription -EQ $adapter.InterfaceDescription).Count -ne 1) {
        throw 'Multiple adapters share the same description. Use Device Manager to configure the intended adapter.'
    }

    $changes = @{ Name = $adapter.Name; NoRestart = $true }
    if ($settings.WakeOnMagicPacket -ne 'Enabled') {
        $changes.WakeOnMagicPacket = 'Enabled'
        Write-Host "Plan: enable WakeOnMagicPacket on $($adapter.Name)."
    }
    if ($settings.WakeOnPattern -eq 'Enabled') {
        $changes.WakeOnPattern = 'Disabled'
        Write-Host "Plan: disable WakeOnPattern on $($adapter.Name)."
    }
    $armDevice = $adapter.InterfaceDescription -notin $armed
    if ($armDevice) { Write-Host "Plan: allow $($adapter.InterfaceDescription) to wake the computer." }
    if ($DisableFastStartup -and $fastStartup -ne 0) {
        Write-Host 'Plan: set HiberbootEnabled to 0 while preserving hibernation.'
    }

    if ($changes.Count -gt 2 -and $PSCmdlet.ShouldProcess($adapter.Name, 'Set adapter Wake-on-LAN settings')) {
        Set-NetAdapterPowerManagement @changes
    }
    if ($armDevice -and $PSCmdlet.ShouldProcess($adapter.InterfaceDescription, 'Arm device wake')) {
        Invoke-WakePowerCfg /deviceenablewake $adapter.InterfaceDescription | Out-Null
    }
    if ($DisableFastStartup -and $fastStartup -ne 0 -and $PSCmdlet.ShouldProcess('HiberbootEnabled', 'Disable Windows Fast Startup')) {
        Set-ItemProperty -LiteralPath $powerKey -Name HiberbootEnabled -Value 0
    }
}

if ($Apply) { Write-Host 'Reboot Windows and verify Wake-on-LAN from the required sleep or power-off state.' }
