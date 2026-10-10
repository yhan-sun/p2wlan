[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$ProcessId,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{32}$')][string]$RequestId,
    [Parameter(Mandatory = $true)][string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$stage = 'initialize'
$broadcastSucceeded = $false
$detail = ''
$exitCode = 1
try {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class P2WlanCtrlCInjector {
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GenerateConsoleCtrlEvent(uint type, uint group);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
}
"@
    $stage = 'attach_console'
    [void][P2WlanCtrlCInjector]::FreeConsole()
    if (-not [P2WlanCtrlCInjector]::AttachConsole([uint32]$ProcessId)) {
        throw [System.ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    # Attaching resets this process's handlers. Protect only the injector
    # from its own broadcast; the existing daemon is still required to stop.
    $stage = 'protect_injector'
    if (-not [P2WlanCtrlCInjector]::SetConsoleCtrlHandler([IntPtr]::Zero, $true)) {
        throw [System.ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $stage = 'broadcast_ctrl_c'
    if (-not [P2WlanCtrlCInjector]::GenerateConsoleCtrlEvent(0, 0)) {
        throw [System.ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $broadcastSucceeded = $true
    $exitCode = 0
} catch {
    $detail = $_.Exception.Message
}
# Keep the ignore attribute until this helper exits. Detaching here resets
# handlers before a pending self-broadcast has necessarily been delivered.
# Process exit releases the console attachment within the parent's deadline.
[ordered]@{
    request_id = $RequestId
    target_process_id = $ProcessId
    broadcast_succeeded = $broadcastSucceeded
    stage = $stage
    detail = $detail
} | ConvertTo-Json | Set-Content -LiteralPath $EvidencePath -Encoding utf8
exit $exitCode
