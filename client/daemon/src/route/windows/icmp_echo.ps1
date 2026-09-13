$ErrorActionPreference = 'Stop'
$parameters = @{
    Direction = 'Inbound'
    Action = 'Allow'
    Enabled = 'True'
    Protocol = 'ICMPv4'
    IcmpType = '8'
    LocalAddress = $cidr
    RemoteAddress = $cidr
    Profile = 'Any'
    InterfaceAlias = [System.Management.Automation.WildcardPattern]::Escape($interface)
    EdgeTraversalPolicy = 'Block'
}
$rule = Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction SilentlyContinue
if ($null -eq $rule) {
    try {
        New-NetFirewallRule -Name $name -DisplayName "P2WLAN ICMPv4 $cidr ($interface)" -Group 'P2WLAN' -PolicyStore PersistentStore @parameters | Out-Null
    } catch {
        $rule = Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction SilentlyContinue
        if ($null -eq $rule) { throw }
    }
}
if ($null -ne $rule) {
    $rule | Set-NetFirewallRule @parameters | Out-Null
}
$verified = @(Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop)
if ($verified.Count -ne 1 -or $verified[0].Enabled -ne 'True' -or $verified[0].Direction -ne 'Inbound' -or $verified[0].Action -ne 'Allow') {
    throw "P2WLAN ICMPv4 rule verification failed for $cidr on $interface"
}
