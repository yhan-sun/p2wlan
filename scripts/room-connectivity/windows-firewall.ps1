$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$template = Get-Content (Join-Path $root 'client/daemon/src/route/windows/icmp_echo.ps1') -Raw
$candidates = @(foreach ($candidate in (Get-NetIPInterface -AddressFamily IPv4 | Where-Object ConnectionState -eq 'Connected')) {
    $addresses = @(Get-NetIPAddress -InterfaceIndex $candidate.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -ne '0.0.0.0' })
    if ($addresses.Count -gt 0) { $candidate }
})
$adapter = $candidates | Sort-Object InterfaceMetric, InterfaceIndex | Select-Object -First 1
if ($null -eq $adapter) { throw 'No connected IPv4 interface for the native firewall regression' }
$interface = [string]$adapter.InterfaceAlias
Write-Output "Native firewall fixture: PowerShell=$($PSVersionTable.PSVersion) interface_index=$($adapter.InterfaceIndex) alias=$interface"
$prefix = 'P2WLAN-ICMP-Test-' + [guid]::NewGuid().ToString('N')
$names = @("$prefix-legacy", "$prefix-a", "$prefix-b")

function Assert-True($condition, $message) {
    if (-not $condition) { throw $message }
}

function Assert-Address($values, $expected) {
    $values = @($values)
    Assert-True ($values.Count -eq 1) 'Address scope must not be broadened'
    $canonical = $values[0].Replace('/255.255.255.0', '/24').Replace('/255.255.0.0', '/16')
    Assert-True ($canonical -eq $expected) "Expected $expected but got $canonical"
}

function Ensure-TestRule($ruleName, $roomCidr) {
    $name = $ruleName
    $cidr = $roomCidr
    try {
        & ([scriptblock]::Create($template))
    } catch {
        Write-Output "Firewall regression failed: name=$name cidr=$cidr interface=$interface"
        Get-NetIPInterface -AddressFamily IPv4 | Format-Table InterfaceIndex, InterfaceAlias, ConnectionState
        Get-NetAdapter -IncludeHidden | Format-Table ifIndex, Name, Status
        throw
    }
}

function Assert-Rule($ruleName, $roomCidr) {
    $rule = Get-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore
    Assert-True ($rule.Enabled -eq 'True' -and $rule.Action -eq 'Allow' -and $rule.Direction -eq 'Inbound') 'Rule must be enabled inbound allow'
    $addresses = $rule | Get-NetFirewallAddressFilter
    Assert-Address $addresses.LocalAddress $roomCidr
    Assert-Address $addresses.RemoteAddress $roomCidr
    $ports = $rule | Get-NetFirewallPortFilter
    Assert-True ($ports.Protocol -eq 'ICMPv4' -or $ports.Protocol -eq '1') 'Only ICMPv4 may be allowed'
    Assert-True (@($ports.IcmpType).Count -eq 1 -and @('8', '8:*') -contains [string]$ports.IcmpType) 'Only echo requests may be allowed'
    $scope = $rule | Get-NetFirewallInterfaceFilter
    Assert-True (@($scope.InterfaceAlias).Count -eq 1 -and $scope.InterfaceAlias -eq $interface) 'Rule must be scoped to its interface'
}

try {
    New-NetFirewallRule -Name $names[0] -DisplayName 'p2wlan Overlay ICMPv4 Echo Request' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -LocalAddress '10.20.0.0/16' -RemoteAddress '10.20.0.0/16' -Enabled False | Out-Null
    Ensure-TestRule $names[1] '10.21.1.0/24'
    Ensure-TestRule $names[2] '10.21.2.0/24'
    Assert-Rule $names[1] '10.21.1.0/24'
    Assert-Rule $names[2] '10.21.2.0/24'
    Set-NetFirewallRule -Name $names[1] -Enabled False -LocalAddress Any -RemoteAddress Any -InterfaceAlias Any | Out-Null
    Ensure-TestRule $names[1] '10.21.1.0/24'
    Assert-Rule $names[1] '10.21.1.0/24'
    Assert-Rule $names[2] '10.21.2.0/24'
    Ensure-TestRule $names[1] '10.21.1.0/24'
    Assert-True (@(Get-NetFirewallRule -Name $names[1]).Count -eq 1) 'Ensure must be idempotent'
    $legacy = Get-NetFirewallRule -Name $names[0]
    Assert-True ($legacy.Enabled -eq 'False') 'Legacy shared rule must not be silently enabled or modified'
    Assert-Address ($legacy | Get-NetFirewallAddressFilter).LocalAddress '10.20.0.0/16'
    Write-Output 'PASS: independent room rules, bounded address/interface/ICMP scope, repair, idempotence, legacy preservation'
} finally {
    foreach ($ruleName in $names) {
        Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
}
