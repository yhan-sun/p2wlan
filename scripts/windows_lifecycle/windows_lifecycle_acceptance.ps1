[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DaemonPath,

    [Parameter(Mandatory = $true)]
    [string]$CliPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidencePath,

    [string]$FlutterReleasePath,
    [string]$FlutterEvidencePath,
    [int]$ProductionCycles = 50,
    [switch]$AttemptRealWintun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) "p2wlan-windows-lifecycle-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
$records = [System.Collections.Generic.List[object]]::new()
$capabilities = [System.Collections.Generic.List[object]]::new()
$serviceRecords = [System.Collections.Generic.List[object]]::new()
$previousDisableTun = $env:P2WLAN_DISABLE_TUN
$previousStateDir = $env:P2WLAN_STATE_DIR

function Add-Capability {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('verified', 'deferred', 'failed')][string]$Status,
        [Parameter(Mandatory = $false)][string]$Detail = ''
    )
    foreach ($existing in @($capabilities | Where-Object { $_.name -eq $Name })) {
        [void]$capabilities.Remove($existing)
    }
    $capabilities.Add([ordered]@{
            name = $Name
            status = $Status
            detail = $Detail
        })
}

function Get-DaemonProcesses {
    @(Get-CimInstance Win32_Process -Filter "Name = 'p2wlan-daemon.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -notmatch '(?i)(^|\s)--build-info(\s|$)' })
}

function Get-ProcessIdList {
    @(Get-DaemonProcesses | ForEach-Object { [int]$_.ProcessId })
}

function Get-DescendantProcessIds {
    param([Parameter(Mandatory = $true)][int]$RootPid)
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $children = [System.Collections.Generic.List[int]]::new()
    $frontier = [System.Collections.Generic.Queue[int]]::new()
    $frontier.Enqueue($RootPid)
    while ($frontier.Count -gt 0) {
        $parent = $frontier.Dequeue()
        foreach ($process in $all | Where-Object { [int]$_.ParentProcessId -eq $parent }) {
            $child = [int]$process.ProcessId
            if (-not $children.Contains($child)) {
                $children.Add($child)
                $frontier.Enqueue($child)
            }
        }
    }
    @($children)
}

function Get-WintunSnapshot {
    @(
        Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '(?i)p2wlan|wintun' -or
                $_.InterfaceDescription -match '(?i)p2wlan|wintun'
            } |
            ForEach-Object { "$($_.Name)|$($_.InterfaceDescription)|$($_.Status)" } |
            Sort-Object
    )
}

function Test-TargetWintunPresent {
    param([string[]]$Snapshot)
    @($Snapshot | Where-Object { $_ -match '(?i)(^|\|)p2wlan-lifecycle(?:\||$)' }).Count -gt 0
}

function Wait-TargetWintunReleased {
    param([Parameter(Mandatory = $true)][int]$TimeoutSeconds = 10)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (-not (Test-TargetWintunPresent -Snapshot (Get-WintunSnapshot))) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $false
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        [int]$listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}

function Test-LoopbackPortReleased {
    param([Parameter(Mandatory = $true)][int]$Port)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
        $true
    } catch {
        $false
    } finally {
        $listener.Stop()
    }
}

function Wait-DaemonReady {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$AuthPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds = 20
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/health" -TimeoutSec 2
            if ($health.StatusCode -ge 200 -and $health.StatusCode -lt 300 -and (Test-Path -LiteralPath $AuthPath)) {
                $token = (Get-Content -LiteralPath $AuthPath -Raw).Trim()
                if ($token) {
                    return $token
                }
            }
        } catch {
            # The daemon can be between instance-lock, diagnostics bind, and
            # auth-file publication. Keep polling inside the bounded budget.
        }
        Start-Sleep -Milliseconds 200
    }
    throw "daemon diagnostics did not become ready at $BaseUrl"
}

function Wait-ProcessExited {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds = 20
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $Process.Refresh()
            if ($Process.HasExited) {
                return [pscustomobject]@{ exited = $true; exit_code = $Process.ExitCode }
            }
        } catch {
            return [pscustomobject]@{ exited = $true; exit_code = $null }
        }
        Start-Sleep -Milliseconds 100
    }
    [pscustomobject]@{ exited = $false; exit_code = $null }
}

function Start-ProductionDaemon {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$DiagnosticsBind
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $DaemonPath
    $startInfo.WorkingDirectory = Split-Path -Parent $DaemonPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
            '--config', $ConfigPath,
            '--control', 'http://127.0.0.1:1',
            '--network', 'windows-lifecycle',
            '--diagnostics-bind', $DiagnosticsBind,
            '--log-file', $LogPath,
            '--manual',
            '--interface', 'p2wlan-lifecycle',
            '--address', '10.20.0.1',
            '--udp-bind', '127.0.0.1:0',
            '--stun', 'none',
            '--socket-pool', 'off'
        )) {
        $null = $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "failed to start $DaemonPath"
    }
    $process.BeginOutputReadLine()
    $process.BeginErrorReadLine()
    $process
}

function Stop-DiagnosticsDaemon {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$Token
    )
    $response = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$BaseUrl/shutdown" -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 5
    if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
        throw "diagnostics shutdown returned HTTP $($response.StatusCode)"
    }
}

function Stop-CliDaemon {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$StateDirectory
    )
    $env:P2WLAN_STATE_DIR = $StateDirectory
    $output = @(& $CliPath --config $ConfigPath down 2>&1 | Out-String)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "p2wlan CLI stop exited with ${exitCode}: $($output -join '')"
    }
}

function Add-ConsoleCtrlHelper {
    if ('P2WlanLifecycleNative' -as [type]) { return }
    Add-Type @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class P2WlanLifecycleNative {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct STARTUPINFO { public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
  [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool GenerateConsoleCtrlEvent(uint type, uint group);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool FreeConsole();
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
  public static int StartInNewProcessGroup(string fileName, string arguments, string cwd) {
    var si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(si); si.dwFlags = 0x00000001; si.wShowWindow = 0;
    PROCESS_INFORMATION pi;
    if (!CreateProcess(fileName, "\"" + fileName + "\" " + arguments, IntPtr.Zero, IntPtr.Zero, false, 0x00000200, IntPtr.Zero, cwd, ref si, out pi)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return (int)pi.dwProcessId;
  }
  public static void SendCtrlC(int processId) {
    // CTRL_C_EVENT cannot be scoped to a process group. Temporarily attach
    // this helper to the daemon's inherited console, with the PowerShell
    // parent detached, so the event reaches only the daemon. Restore the
    // parent console before returning to the acceptance script.
    FreeConsole();
    try {
      if (!AttachConsole((uint)processId)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
      if (!GenerateConsoleCtrlEvent(0, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    } finally {
      FreeConsole();
      AttachConsole(0xffffffff);
    }
  }
}
'@
}

function Invoke-ProductionCycle {
    param(
        [Parameter(Mandatory = $true)][int]$Cycle,
        [Parameter(Mandatory = $true)][ValidateSet('diagnostics', 'cli', 'ctrl_c')][string]$Entrypoint,
        [Parameter(Mandatory = $true)][bool]$RealWintun
    )
    $cycleRoot = Join-Path $runRoot "cycle-$Cycle"
    New-Item -ItemType Directory -Path $cycleRoot -Force | Out-Null
    $configPath = Join-Path $cycleRoot 'config.json'
    $logPath = Join-Path $cycleRoot 'daemon.log'
    $port = Get-FreeLoopbackPort
    $baseUrl = "http://127.0.0.1:$port"
    $authPath = Join-Path $cycleRoot 'p2wlan-daemon.diag-auth'
    $beforeWintun = Get-WintunSnapshot
    $beforePids = Get-ProcessIdList
    $process = $null
    $ctrlCProcessId = $null
    $startSucceeded = $false
    $stopRequested = $false
    $forcedTermination = $false
    $processExited = $false
    $exitCode = $null
    $childrenGone = $false
    $portReleased = $false
    $authRemoved = $false
    $wintunStale = $false
    $wintunObserved = $false
    $daemonProcessesClean = $false
    $childPids = @()
    $detail = ''

    try {
        if ($RealWintun -and (Test-TargetWintunPresent -Snapshot $beforeWintun)) {
            throw 'p2wlan-lifecycle Wintun adapter was already present before the cycle'
        }
        if ($RealWintun) {
            Remove-Item Env:P2WLAN_DISABLE_TUN -ErrorAction SilentlyContinue
        } else {
            $env:P2WLAN_DISABLE_TUN = '1'
        }
        if ($Entrypoint -eq 'ctrl_c') {
            Add-ConsoleCtrlHelper
            $arguments = "--config `"$configPath`" --control http://127.0.0.1:1 --network windows-lifecycle --diagnostics-bind 127.0.0.1:$port --log-file `"$logPath`" --manual --interface p2wlan-lifecycle --address 10.20.0.1 --udp-bind 127.0.0.1:0 --stun none --socket-pool off"
            $ctrlCProcessId = [P2WlanLifecycleNative]::StartInNewProcessGroup($DaemonPath, $arguments, (Split-Path -Parent $DaemonPath))
            $process = Get-Process -Id $ctrlCProcessId -ErrorAction Stop
        } else {
            $process = Start-ProductionDaemon -ConfigPath $configPath -LogPath $logPath -DiagnosticsBind "127.0.0.1:$port"
        }
        $token = Wait-DaemonReady -BaseUrl $baseUrl -AuthPath $authPath
        $startSucceeded = $true
        $wintunDeadline = [DateTime]::UtcNow.AddSeconds(5)
        while ($RealWintun -and [DateTime]::UtcNow -lt $wintunDeadline) {
            $duringWintun = Get-WintunSnapshot
            if (Test-TargetWintunPresent -Snapshot $duringWintun) {
                $wintunObserved = $true
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if ($RealWintun -and -not $wintunObserved) {
            throw 'daemon became ready without an observable p2wlan-lifecycle Wintun adapter'
        }
        $childPids = Get-DescendantProcessIds -RootPid $process.Id
        switch ($Entrypoint) {
            'diagnostics' { Stop-DiagnosticsDaemon -BaseUrl $baseUrl -Token $token }
            'cli' { Stop-CliDaemon -ConfigPath $configPath -StateDirectory $cycleRoot }
            'ctrl_c' { [P2WlanLifecycleNative]::SendCtrlC($process.Id) }
        }
        $stopRequested = $true
        if ($Entrypoint -eq 'ctrl_c') {
            $result = Wait-ProcessExited -Process $process -TimeoutSeconds 5
        } else {
            $result = Wait-ProcessExited -Process $process -TimeoutSeconds 20
        }
        $processExited = $result.exited
        $exitCode = $result.exit_code
        if (-not $processExited) {
            throw "daemon did not exit after $Entrypoint"
        }
        if ($exitCode -ne 0) {
            throw "daemon exited with code $exitCode after $Entrypoint"
        }
        $childrenAfterExit = @(Get-DescendantProcessIds -RootPid $process.Id)
        $observedChildPids = @($childPids) + @($childrenAfterExit)
        $observedChildPids = @($observedChildPids | Sort-Object -Unique)
        $childrenGone = @($observedChildPids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }).Count -eq 0
        $portReleased = Test-LoopbackPortReleased -Port $port
        $authRemoved = -not (Test-Path -LiteralPath $authPath)
        $afterWintun = Get-WintunSnapshot
        $wintunStale = if ($RealWintun) { -not (Wait-TargetWintunReleased) } else { Test-TargetWintunPresent -Snapshot $afterWintun }
        $daemonProcessesClean = @(
            Get-ProcessIdList | Where-Object { $beforePids -notcontains $_ }
        ).Count -eq 0
        if (-not $childrenGone) { throw "child process remained after daemon exit" }
        if (-not $portReleased) { throw "diagnostics port $port was not released" }
        if (-not $authRemoved) { throw "diagnostics auth file remained" }
        if (-not $daemonProcessesClean) { throw "a new p2wlan-daemon process remained after daemon exit" }
        if ($RealWintun -and $wintunStale) { throw "p2wlan-lifecycle Wintun adapter remained after daemon exit" }
    } catch {
        $detail = $_.Exception.Message
        $running = $false
        try { $running = $process -and -not $process.HasExited } catch { $running = $false }
        if ($running) {
            # Emergency cleanup is deliberately recorded as forceful failure;
            # it can never make this cycle a graceful pass.
            try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch {}
            $forcedTermination = $true
        }
        if ($process) {
            $result = Wait-ProcessExited -Process $process -TimeoutSeconds 5
            $processExited = $result.exited
            $exitCode = $result.exit_code
        }
        $portReleased = Test-LoopbackPortReleased -Port $port
        $authRemoved = -not (Test-Path -LiteralPath $authPath)
        $afterWintun = Get-WintunSnapshot
        $wintunStale = -not (Wait-TargetWintunReleased)
        $daemonProcessesClean = @(
            Get-ProcessIdList | Where-Object { $beforePids -notcontains $_ }
        ).Count -eq 0
    }
    [pscustomobject]@{
        cycle = $Cycle
        entrypoint = $Entrypoint
        mode = 'production'
        real_wintun = $RealWintun
        start_succeeded = $startSucceeded
        graceful_stop = $stopRequested -and $processExited -and $exitCode -eq 0 -and -not $forcedTermination
        forced_termination = $forcedTermination
        process_exited = $processExited
        process_exit_code = $exitCode
        children_gone = $childrenGone
        diagnostics_port_released = $portReleased
        auth_token_removed = $authRemoved
        wintun_stale = $wintunStale
        wintun_observed = $wintunObserved
        daemon_processes_clean = $daemonProcessesClean
        pid = if ($process) { $process.Id } else { $null }
        diagnostics_port = $port
        detail = $detail
        baseline_daemon_pids = @($beforePids)
        baseline_wintun = @($beforeWintun)
    }
}

function Invoke-FlutterTrayNoAdapterExit {
    if ([string]::IsNullOrWhiteSpace($FlutterReleasePath)) {
        return [pscustomobject]@{
            status = 'deferred'
            detail = 'Flutter release executable was not supplied'
            process_exited = $false
            exit_code = $null
            daemon_processes_clean = $true
            forced_termination = $false
        }
    }
    if (-not (Test-Path -LiteralPath $FlutterReleasePath)) {
        return [pscustomobject]@{
            status = 'failed'
            detail = "Flutter release executable not found: $FlutterReleasePath"
            process_exited = $false
            exit_code = $null
            daemon_processes_clean = $false
            forced_termination = $false
        }
    }

    $trayRoot = Join-Path $runRoot 'flutter-tray-no-adapter'
    New-Item -ItemType Directory -Path $trayRoot -Force | Out-Null
    $beforePids = Get-ProcessIdList
    $process = $null
    $forcedTermination = $false
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = [System.IO.Path]::GetFullPath($FlutterReleasePath)
        $startInfo.WorkingDirectory = Split-Path -Parent $startInfo.FileName
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $false
        $startInfo.Environment['P2WLAN_WINDOWS_TRAY_LIFECYCLE_TEST'] = 'no-adapter-exit'
        $startInfo.Environment['P2WLAN_ENABLE_FLUTTER_TRAY'] = '1'
        # Keep this release run isolated from any persisted desktop settings;
        # no daemon is intentionally started for the no-adapter regression.
        $startInfo.Environment['APPDATA'] = $trayRoot
        $startInfo.Environment['LOCALAPPDATA'] = $trayRoot
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw "failed to start Flutter release app" }
        $result = Wait-ProcessExited -Process $process -TimeoutSeconds 30
        if (-not $result.exited) {
            try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch {}
            $forcedTermination = $true
            throw 'Flutter release tray app did not exit within the bounded no-adapter budget'
        }
        $afterPids = Get-ProcessIdList
        $daemonProcessesClean = @(
            $afterPids | Where-Object { $beforePids -notcontains $_ }
        ).Count -eq 0
        if (-not $daemonProcessesClean) {
            throw 'Flutter release tray no-adapter test left a daemon process running'
        }
        if ($result.exit_code -ne 0) {
            throw "Flutter release tray app exited with code $($result.exit_code)"
        }
        return [pscustomobject]@{
            status = 'verified'
            detail = 'release Flutter tray initialized and exited cleanly without a virtual adapter'
            process_exited = $true
            exit_code = $result.exit_code
            daemon_processes_clean = $daemonProcessesClean
            forced_termination = $false
        }
    } catch {
        $detail = $_.Exception.Message
        $daemonProcessesClean = @(
            Get-ProcessIdList | Where-Object { $beforePids -notcontains $_ }
        ).Count -eq 0
        return [pscustomobject]@{
            status = 'failed'
            detail = $detail
            process_exited = if ($process) { $process.HasExited } else { $false }
            exit_code = if ($process -and $process.HasExited) { $process.ExitCode } else { $null }
            daemon_processes_clean = $daemonProcessesClean
            forced_termination = $forcedTermination
        }
    }
}

function Import-FlutterLifecycleEvidence {
    param([Parameter(Mandatory = $true)][string]$ExpectedHeadSha)
    if ([string]::IsNullOrWhiteSpace($FlutterEvidencePath)) {
        Add-Capability -Name 'ui_stop' -Status 'deferred' -Detail 'Flutter UI evidence path was not supplied'
        return
    }
    if (-not (Test-Path -LiteralPath $FlutterEvidencePath)) {
        Add-Capability -Name 'ui_stop' -Status 'failed' -Detail "Flutter UI evidence was not written: $FlutterEvidencePath"
        return
    }
    try {
        $flutter = Get-Content -LiteralPath $FlutterEvidencePath -Raw | ConvertFrom-Json
        if ($flutter.head_sha -ne $ExpectedHeadSha) {
            Add-Capability -Name 'ui_stop' -Status 'failed' -Detail "Flutter UI evidence head_sha=$($flutter.head_sha) does not match $ExpectedHeadSha"
            return
        }
        foreach ($cycle in @($flutter.cycles)) { $records.Add($cycle) }
        $uiCapability = @($flutter.capabilities | Where-Object { $_.name -eq 'ui_stop' } | Select-Object -First 1)
        if ($uiCapability.Count -ne 1) {
            Add-Capability -Name 'ui_stop' -Status 'failed' -Detail 'Flutter UI evidence did not contain a ui_stop capability'
            return
        }
        Add-Capability -Name 'ui_stop' -Status $uiCapability[0].status -Detail ([string]$uiCapability[0].detail)
    } catch {
        Add-Capability -Name 'ui_stop' -Status 'failed' -Detail "Flutter UI evidence could not be imported: $($_.Exception.Message)"
    }
}

function Invoke-ServiceCycle {
    param([ValidateSet('stop', 'preshutdown')][string]$Control)
    $serviceName = "p2wlan-lifecycle-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $serviceRoot = Join-Path $runRoot $serviceName
    New-Item -ItemType Directory -Path $serviceRoot -Force | Out-Null
    $configPath = Join-Path $serviceRoot 'config.json'
    $logPath = Join-Path $serviceRoot 'service.log'
    $binPath = '"{0}" --windows-service --windows-service-name {1} --config "{2}" --control http://127.0.0.1:1 --network windows-lifecycle --manual --diagnostics-disable --log-file "{3}" --interface p2wlan-lifecycle --address 10.20.0.1 --udp-bind 127.0.0.1:0 --stun none --socket-pool off' -f $DaemonPath, $serviceName, $configPath, $logPath
    $beforeWintun = Get-WintunSnapshot
    $status = 'failed'
    $detail = ''
    $processId = $null
    $processGone = $false
    $wintunStale = $false
    $wintunObserved = $false
    $previousServiceDisableTun = $env:P2WLAN_DISABLE_TUN
    try {
        # Service control must exercise the real Wintun path even if a manual
        # invocation of this script was configured for no-TUN production
        # cycles. The workflow always requests real Wintun explicitly.
        Remove-Item Env:P2WLAN_DISABLE_TUN -ErrorAction SilentlyContinue
        if (Test-TargetWintunPresent -Snapshot $beforeWintun) {
            throw 'p2wlan-lifecycle Wintun adapter was already present before the service cycle'
        }
        & sc.exe create $serviceName binPath= $binPath start= demand DisplayName= 'P2WLAN lifecycle acceptance' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe create returned $LASTEXITCODE" }
        & sc.exe start $serviceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe start returned $LASTEXITCODE" }
        $deadline = [DateTime]::UtcNow.AddSeconds(25)
        do {
            Start-Sleep -Milliseconds 250
            $query = (& sc.exe query $serviceName | Out-String)
            if ($query -match 'STATE\s+:\s+4\s+RUNNING') { break }
            if ($query -match 'STATE\s+:\s+1\s+STOPPED') { throw "service stopped before reaching RUNNING" }
        } while ([DateTime]::UtcNow -lt $deadline)
        $queryEx = (& sc.exe queryex $serviceName | Out-String)
        $pidMatch = [regex]::Match($queryEx, 'PID\s+\:\s+(\d+)')
        if ($pidMatch.Success) { $processId = [int]$pidMatch.Groups[1].Value }
        if (-not $processId) { throw 'SCM did not expose a service process id' }
        $wintunDeadline = [DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $wintunDeadline) {
            $duringWintun = Get-WintunSnapshot
            if (Test-TargetWintunPresent -Snapshot $duringWintun) {
                $wintunObserved = $true
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $wintunObserved) { throw 'SCM reported RUNNING without an observable p2wlan-lifecycle Wintun adapter' }
        if ($Control -eq 'stop') {
            & sc.exe stop $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "sc.exe stop returned $LASTEXITCODE" }
        } else {
            # PRESHUTDOWN is an SCM-delivered control. GitHub runners do not
            # permit a job to shut down/log off the host, so only accept this
            # as verified if the SCM actually delivers control 15.
            & sc.exe control $serviceName 15 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "SCM did not deliver SERVICE_CONTROL_PRESHUTDOWN (sc.exe exit $LASTEXITCODE)" }
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(25)
        do {
            Start-Sleep -Milliseconds 250
            $query = (& sc.exe query $serviceName | Out-String)
            if ($query -match 'STATE\s+:\s+1\s+STOPPED') { $status = 'verified'; break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($status -ne 'verified') { throw "service did not reach STOPPED within the bounded budget" }
        $processDeadline = [DateTime]::UtcNow.AddSeconds(10)
        while ((Get-Process -Id $processId -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $processDeadline) {
            Start-Sleep -Milliseconds 250
        }
        $processGone = $null -eq (Get-Process -Id $processId -ErrorAction SilentlyContinue)
        if (-not $processGone) { throw "service process $processId remained after SCM $Control" }
        $serviceLog = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Raw } else { '' }
        $expectedReason = if ($Control -eq 'stop') { 'SERVICE_STOP' } else { 'SERVICE_PRESHUTDOWN' }
        if ($serviceLog -notmatch [regex]::Escape("event $expectedReason")) {
            throw "service log did not prove delivery of $expectedReason"
        }
        $status = 'verified'
    } catch {
        $detail = $_.Exception.Message
        $status = 'failed'
        if ($Control -eq 'preshutdown' -and ($detail -match 'PRESHUTDOWN|control 15|not deliver')) {
            $status = 'deferred'
        }
    } finally {
        & sc.exe stop $serviceName | Out-Null
        $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(10)
        while ($processId -and (Get-Process -Id $processId -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $cleanupDeadline) {
            Start-Sleep -Milliseconds 250
        }
        $processGone = $processId -and $null -eq (Get-Process -Id $processId -ErrorAction SilentlyContinue)
        & sc.exe delete $serviceName | Out-Null
        if ($previousServiceDisableTun) { $env:P2WLAN_DISABLE_TUN = $previousServiceDisableTun } else { Remove-Item Env:P2WLAN_DISABLE_TUN -ErrorAction SilentlyContinue }
    }
    $afterWintun = Get-WintunSnapshot
    $wintunStale = Test-TargetWintunPresent -Snapshot $afterWintun
    $serviceRecords.Add([pscustomobject]@{
            name = $serviceName
            control = $Control
            status = $status
            detail = $detail
            process_id = $processId
            process_gone = [bool]$processGone -and (@((Get-DaemonProcesses)).Count -eq 0)
            wintun_observed = $wintunObserved
            wintun_stale = $wintunStale
            baseline_wintun = @($beforeWintun)
        })
}

try {
    if (-not (Test-Path -LiteralPath $DaemonPath)) { throw "daemon binary not found: $DaemonPath" }
    if (-not (Test-Path -LiteralPath $CliPath)) { throw "CLI binary not found: $CliPath" }
    $RealWintun = [bool]$AttemptRealWintun
    for ($cycle = 1; $cycle -le $ProductionCycles; $cycle++) {
        $entrypoint = switch (($cycle - 1) % 3) {
            0 { 'diagnostics' }
            1 { 'cli' }
            default { 'ctrl_c' }
        }
        $record = Invoke-ProductionCycle -Cycle $cycle -Entrypoint $entrypoint -RealWintun $RealWintun
        $records.Add($record)
        if (-not $record.graceful_stop) {
            throw "production cycle $cycle did not prove graceful cleanup: $($record.detail)"
        }
    }

    Invoke-ServiceCycle -Control stop
    Invoke-ServiceCycle -Control preshutdown

    Add-Capability -Name 'production_start_stop' -Status 'verified' -Detail "$ProductionCycles production daemon cycles completed"
    Add-Capability -Name 'diagnostics_port_release' -Status 'verified' -Detail 'every production cycle rebound the same loopback port'
    Add-Capability -Name 'child_process_cleanup' -Status 'verified' -Detail 'every production cycle checked descendants'
    Add-Capability -Name 'cli_stop' -Status 'verified' -Detail 'CLI stop was exercised in rotating production cycles'
    Add-Capability -Name 'ctrl_c' -Status 'verified' -Detail 'CTRL_C_EVENT was delivered by a new-process-group helper'
    Add-Capability -Name 'service_stop' -Status (($serviceRecords | Where-Object control -eq 'stop' | Select-Object -First 1).status) -Detail (($serviceRecords | Where-Object control -eq 'stop' | Select-Object -First 1).detail)
    Add-Capability -Name 'service_preshutdown' -Status (($serviceRecords | Where-Object control -eq 'preshutdown' | Select-Object -First 1).status) -Detail (($serviceRecords | Where-Object control -eq 'preshutdown' | Select-Object -First 1).detail)
    Add-Capability -Name 'wintun_ownership' -Status $(if ($RealWintun) { 'verified' } else { 'deferred' }) -Detail $(if ($RealWintun) { 'real Wintun mode checked after every production cycle' } else { 'real Wintun mode was not requested' })
} catch {
    Add-Capability -Name 'production_start_stop' -Status 'failed' -Detail $_.Exception.Message
    Add-Capability -Name 'diagnostics_port_release' -Status 'failed' -Detail 'production loop aborted before all cycles completed'
    Add-Capability -Name 'child_process_cleanup' -Status 'failed' -Detail 'production loop aborted before all cycles completed'
    Add-Capability -Name 'cli_stop' -Status 'failed' -Detail $_.Exception.Message
    Add-Capability -Name 'ctrl_c' -Status 'failed' -Detail $_.Exception.Message
    Add-Capability -Name 'service_stop' -Status 'failed' -Detail $_.Exception.Message
    Add-Capability -Name 'service_preshutdown' -Status 'deferred' -Detail 'not reached because the production loop failed'
    Add-Capability -Name 'wintun_ownership' -Status $(if ($AttemptRealWintun) { 'failed' } else { 'deferred' }) -Detail $_.Exception.Message
}

if ($serviceRecords.Count -eq 0) {
    Add-Capability -Name 'service_stop' -Status 'failed' -Detail 'service control cycle did not run'
    Add-Capability -Name 'service_preshutdown' -Status 'deferred' -Detail 'service control cycle did not run'
}

# These hooks require a host logoff/shutdown and would terminate the hosted
# job itself. Record the limitation explicitly; never emit a verified pass.
Add-Capability -Name 'logoff_hook' -Status 'deferred' -Detail 'GitHub-hosted job cannot log off the runner without terminating the job'
Add-Capability -Name 'shutdown_hook' -Status 'deferred' -Detail 'GitHub-hosted job cannot shut down the runner without terminating the job'

$evidenceHeadSha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { 'unknown' }
Import-FlutterLifecycleEvidence -ExpectedHeadSha $evidenceHeadSha
$trayResult = Invoke-FlutterTrayNoAdapterExit
Add-Capability -Name 'flutter_release_tray_no_adapter_exit' -Status $trayResult.status -Detail $trayResult.detail

$evidence = [ordered]@{
    schema_version = 1
    head_sha = $evidenceHeadSha
    runner_os = 'windows-latest'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    capabilities = @($capabilities)
    cycles = @($records)
    service_controls = @($serviceRecords)
    flutter_tray = [ordered]@{
        process_exited = $trayResult.process_exited
        exit_code = $trayResult.exit_code
        daemon_processes_clean = $trayResult.daemon_processes_clean
        forced_termination = $trayResult.forced_termination
        detail = $trayResult.detail
    }
    wer = [ordered]@{
        event_ids_checked = @(1000, 1001)
        events = @()
        note = 'WER events are added by the workflow after this script returns.'
    }
}
$parent = Split-Path -Parent $EvidencePath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $EvidencePath -Encoding utf8

if ($previousDisableTun) { $env:P2WLAN_DISABLE_TUN = $previousDisableTun } else { Remove-Item Env:P2WLAN_DISABLE_TUN -ErrorAction SilentlyContinue }
if ($previousStateDir) { $env:P2WLAN_STATE_DIR = $previousStateDir } else { Remove-Item Env:P2WLAN_STATE_DIR -ErrorAction SilentlyContinue }

Write-Host "Windows lifecycle evidence written to $EvidencePath"
