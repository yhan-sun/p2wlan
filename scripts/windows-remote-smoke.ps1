param(
    [switch]$Tun,
    [string]$AliHost = "47.109.40.237",
    [string]$AliKey = "$HOME\.ssh\ali.pem",
    [string]$RemoteBase = "/tmp/p2wlan-remote-test",
    [string]$StunServer = "74.125.250.129:19302",
    [int]$Port = (19000 + (Get-Random -Minimum 0 -Maximum 500)),
    [int]$AliUdp = (25000 + (Get-Random -Minimum 0 -Maximum 500)),
    [int]$WinUdp = 0,
    [int]$AliDiag = (39200 + (Get-Random -Minimum 0 -Maximum 300)),
    [int]$WinDiag = 0
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$DaemonBin = Join-Path $RootDir "target\debug\p2pnet-daemon.exe"
$Mode = if ($Tun) { "tun" } else { "notun" }
$TestId = "windows-$Mode-$PID"
$RemoteRun = "$RemoteBase/$TestId"
$LocalRun = Join-Path $env:TEMP "p2wlan-windows-$Mode-$PID"
$WinConfig = Join-Path $LocalRun "windows.json"
$AliConfig = "$RemoteRun/ali.json"
$AliIf = "p2wwali"
if ($WinUdp -eq 0) { $WinUdp = $AliUdp + 1 }
if ($WinDiag -eq 0) { $WinDiag = $AliDiag + 1 }
$script:Success = $false

function Invoke-Remote {
    param([Parameter(Mandatory = $true)][string]$Command)
    & ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i $AliKey "root@$AliHost" $Command
}

function Stop-RemoteTest {
    try {
        Invoke-Remote "for p in `$(pgrep -f '^$RemoteBase/' || true); do /bin/kill -9 `$p 2>/dev/null || true; done; ip route del 10.20.0.0/16 2>/dev/null || true; ip link del '$AliIf' 2>/dev/null || true" | Out-Null
    } catch {
    }
}

function Stop-LocalTest {
    if ($script:WinProcess -and -not $script:WinProcess.HasExited) {
        Stop-Process -Id $script:WinProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($Tun) {
        Get-NetRoute -DestinationPrefix "10.20.0.0/16" -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -like "p2pnet*" -or $_.InterfaceAlias -like "p2wlan*" } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($script:Success) {
        Remove-Item -Recurse -Force $LocalRun -ErrorAction SilentlyContinue
    } else {
        Write-Host "[windows-smoke] preserved local logs: $LocalRun"
    }
}

function Get-TopVirtualIp {
    param([string]$JsonText)
    $match = [regex]::Matches($JsonText, '"virtual_ip":\s*"([0-9.]+)"')
    if ($match.Count -eq 0) { return "" }
    return $match[$match.Count - 1].Groups[1].Value
}

function Wait-Http {
    param([string]$Url)
    for ($i = 0; $i -lt 50; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2 | Out-Null
            return $true
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    return $false
}

try {
    if (!(Test-Path $DaemonBin)) {
        Push-Location $RootDir
        cargo build -p p2pnet-daemon
        Pop-Location
    }

    if ($Tun) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Run -Tun mode from an elevated PowerShell session."
        }
    }

    New-Item -ItemType Directory -Force $LocalRun | Out-Null
    Write-Host "[windows-smoke] mode: $Mode"
    Write-Host "[windows-smoke] local run: $LocalRun"
    Write-Host "[windows-smoke] remote run: $RemoteRun"

    Stop-RemoteTest
    Invoke-Remote "mkdir -p '$RemoteRun'; cd '$RemoteRun'; env PORT=$Port DB_PATH='$RemoteRun/control.db' JWT_SECRET=smoke nohup '$RemoteBase/control-server' >server.log 2>&1 & echo `$! >server.pid" | Out-Null
    if (!(Wait-Http "http://$AliHost`:$Port/health")) {
        Invoke-Remote "tail -100 '$RemoteRun/server.log' || true"
        throw "control server did not become healthy"
    }

    $register = Invoke-RestMethod -Method Post -Uri "http://$AliHost`:$Port/api/v1/register" -ContentType "application/json" -Body '{"email":"windows-smoke@example.com","password":"passw0rd"}'
    $Token = $register.token
    if (!$Token) { throw "failed to parse auth token" }

    $remoteTunEnv = if ($Tun) { "" } else { "P2WLAN_DISABLE_TUN=1" }
    $localTunEnv = if ($Tun) { @{} } else { @{ P2WLAN_DISABLE_TUN = "1" } }

    Invoke-Remote "cd '$RemoteRun'; env $remoteTunEnv RUST_LOG=info nohup '$RemoteBase/p2pnet-daemon' --config '$AliConfig' --control 'http://$AliHost`:$Port' --network default --token '$Token' --device-name ali-windows-$Mode --interface '$AliIf' --udp-bind 0.0.0.0:$AliUdp --udp-advertise '$AliHost`:$AliUdp' --diagnostics-bind 127.0.0.1:$AliDiag --heartbeat-interval 5 >ali.log 2>&1 & echo `$! >ali.pid" | Out-Null

    $env:RUST_LOG = "info"
    if ($Tun) {
        Remove-Item Env:P2WLAN_DISABLE_TUN -ErrorAction SilentlyContinue
    }
    foreach ($key in $localTunEnv.Keys) { Set-Item -Path "env:$key" -Value $localTunEnv[$key] }
    $script:WinProcess = Start-Process -FilePath $DaemonBin -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $LocalRun "windows.log") -RedirectStandardError (Join-Path $LocalRun "windows.err") -ArgumentList @(
        "--config", $WinConfig,
        "--control", "http://$AliHost`:$Port",
        "--network", "default",
        "--token", $Token,
        "--device-name", "windows-$Mode",
        "--udp-bind", "0.0.0.0:$WinUdp",
        "--stun", $StunServer,
        "--diagnostics-bind", "127.0.0.1:$WinDiag",
        "--heartbeat-interval", "5"
    )

    $passDirect = $false
    for ($i = 0; $i -lt 120; $i++) {
        $WinStatus = ""
        $AliStatus = ""
        try { $WinStatus = & $DaemonBin --status --diagnostics-url "http://127.0.0.1:$WinDiag/status" 2>$null | Out-String } catch {}
        try { $AliStatus = Invoke-Remote "'$RemoteBase/p2pnet-daemon' --status --diagnostics-url http://127.0.0.1:$AliDiag/status" | Out-String } catch {}
        if ($WinStatus -match '"state":\s*"direct"' -and $AliStatus -match '"state":\s*"direct"') {
            $passDirect = $true
            break
        }
        Start-Sleep -Seconds 1
    }

    Write-Host "--- windows log ---"
    Get-Content (Join-Path $LocalRun "windows.log") -ErrorAction SilentlyContinue |
        Select-String 'Control plane registration confirmed|Prepared [0-9]+ UDP candidate endpoints|Sent WireGuard handshake initiation|Received peer offer|Received peer answer|Installed WireGuard|Sent [0-9]+ UDP punch probes|state:' |
        ForEach-Object { $_.Line }
    Write-Host "--- ali log ---"
    Invoke-Remote "grep -E 'Control plane registration confirmed|Prepared [0-9]+ UDP candidate endpoints|Received peer offer|Received peer answer|Installed WireGuard|Sent [0-9]+ UDP punch probes|state:' '$RemoteRun/ali.log' || true"
    Write-Host "--- windows status ---"
    Write-Host $WinStatus
    Write-Host "--- ali status ---"
    Write-Host $AliStatus

    if (!$passDirect) { throw "direct path did not become healthy" }

    if ($Tun) {
        $WinVip = Get-TopVirtualIp $WinStatus
        $AliVip = Get-TopVirtualIp $AliStatus
        if (!$WinVip -or !$AliVip -or $WinVip -eq $AliVip) {
            throw "could not extract distinct VIPs (windows=$WinVip ali=$AliVip)"
        }
        Write-Host "[windows-smoke] Windows VIP: $WinVip"
        Write-Host "[windows-smoke] Ali VIP: $AliVip"
        Get-NetRoute -DestinationPrefix "10.20.0.0/16" -ErrorAction SilentlyContinue | Format-Table -AutoSize
        ping -n 3 -S $WinVip $AliVip
        Invoke-Remote "ping -I '$AliVip' -c 3 '$WinVip'"
    }

    Write-Host "[windows-smoke] PASS: Windows $Mode smoke completed"
    $script:Success = $true
} finally {
    Stop-LocalTest
    Stop-RemoteTest
}
