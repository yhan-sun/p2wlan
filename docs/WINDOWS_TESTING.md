# Windows Remote Smoke Testing

This project can test a Windows client against a public Linux server.

## Requirements

- Windows 10/11.
- PowerShell 5+.
- `p2pnet-daemon.exe` built locally.
- `wintun.dll` available next to `p2pnet-daemon.exe`, next to the desktop app,
  in `PATH`, or pointed to by `P2WLAN_WINTUN_DLL`.
- `ssh.exe` available in `PATH`.
- For `-Tun` mode: elevated Administrator PowerShell.

Build on Windows:

```powershell
cargo build -p p2pnet-daemon
```

## Portable release package

GitHub Actions builds a Windows x64 portable package when a `v*` tag is pushed,
or when the `Release` workflow is run manually.

The zip contains:

- `p2wlan-desktop.exe`
- `p2pnet-daemon.exe`
- `wintun.dll`
- `README-WINDOWS.txt`

Keep those three binaries in the same folder. Start `p2wlan-desktop.exe`, login
or register, then click `授权启动 TUN` and approve Windows UAC. The app does not
store the Windows password; authorization is handled by Windows.

## No-TUN NAT smoke

This does not require Administrator privileges and does not change local routes:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows-remote-smoke.ps1
```

Success means both diagnostics report:

```json
"state": "direct"
"active_path": "direct"
```

## Real Wintun smoke

Run from an elevated Administrator PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows-remote-smoke.ps1 -Tun
```

Success means:

- The Windows peer reaches the Linux peer VIP with `ping`.
- The Linux peer reaches the Windows peer VIP with `ping`.
- Both directions report `0% packet loss`.

The script cleans up:

- local daemon process
- remote daemon/control processes
- remote Linux `10.20.0.0/16` route
- remote Linux test TUN interface
- Windows active-store `10.20.0.0/16` route on the test interface

Useful overrides:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows-remote-smoke.ps1 `
  -AliHost 47.109.40.237 `
  -AliKey "$HOME\.ssh\ali.pem" `
  -StunServer 74.125.250.129:19302
```

If Wintun mode fails, the script preserves the local log directory printed as
`[windows-smoke] local run: ...`. Collect:

```powershell
Get-NetRoute -DestinationPrefix 10.20.0.0/16
Get-NetIPConfiguration
Get-Content <local-run-path>\windows.log
Get-Content <local-run-path>\windows.err
```
