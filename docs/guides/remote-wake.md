# Windows 远程开机

远程开机需要一台常在线代理和一台启用了有线 Wake-on-LAN 的目标机。请求方通过 HTTPS 访问 Control，代理从 Control 领取任务，并在目标所在局域网发送魔术包。发起请求前可以保持本机 VPN 断开。

## 配置 Windows 目标

1. 用网线连接目标机。在 BIOS 或 UEFI 中开启 Wake-on-LAN 或 PCIe 唤醒，检查断电节能设置是否会切断网卡待机供电。
2. 在 Windows 网卡属性中启用魔术包唤醒。关闭快速启动前先确认网卡和固件的说明。Windows 官方支持 S3 睡眠和显式 S4 休眠的 Wake-on-LAN。S5 关机唤醒取决于硬件和固件，需在自己的机器上验证。[Microsoft 系统电源状态](https://learn.microsoft.com/windows/win32/power/system-power-states)
3. 从源码目录运行以下脚本查看有线网卡、电源状态和已启用的唤醒设备。需要配置时，以管理员身份运行带 `-Apply` 的命令，按实际网卡名称替换 `Ethernet`。

```powershell
powershell -File .\scripts\windows\enable-wol.ps1
powershell -File .\scripts\windows\enable-wol.ps1 -InterfaceName 'Ethernet' -Apply
powercfg /devicequery wake_armed
```

只有在需要关闭快速启动做对照测试时，才在 `-Apply` 命令后加 `-DisableFastStartup`。该选项保留休眠功能。

目标机登录 P2WLAN 并至少成功联网一次。在目标对应的 Windows 配置中启用登记，再重启 daemon。CLI 可用时可执行 `p2wlan config set wake-allow-remote true`。

## 配置常在线代理

把代理放在目标的同一广播域。不同 VLAN 或访客网络通常无法互相接收广播。P2WLAN 房间提供账号和设备的授权边界，局域网位置由使用者核对。

先在代理上手动发送。将示例 MAC 替换为目标有线网卡地址，按系统填写代理侧网卡名。OpenWrt 通常使用持有 LAN IPv4 地址的 `br-lan`。

```sh
p2wlan wake send --mac 02:00:00:00:00:01 --interface br-lan
```

目标能从选定电源状态唤醒后，在代理加入目标所在的个人网络或房间，切换代理开关并重启对应 daemon。下列命令启动默认配置。房间实例应使用该实例自己的 `--config`，并按其生命周期重启。

```sh
p2wlan down
p2wlan config set wake-proxy-interface br-lan
p2wlan wake proxy on
p2wlan up
p2wlan wake status
```

OpenWrt 默认个人网络实例可由 procd 管理。独立房间实例需在路由器重启后重新连接，详见 [OpenWrt 路由器节点](openwrt.md#服务和升级)。

## 发起远程开机

在 P2WLAN 设备页工具栏打开“远程开机”，或从房间的设备管理菜单打开对应设备的唤醒对话框。如果 Control 返回多台代理，选择和目标实际处于同一局域网的一台。任务进入 `sent` 表示代理已把魔术包交给本机网络。界面最多等待 120 秒，并以目标重新在线确认开机。

手填目标适用于没有安装 P2WLAN 的局域网设备。个人网络由账号本人登记，房间由房主登记。在目标所在网络登记一个名称和有线 MAC，使用界面选择目标和代理并发送。手填目标没有设备在线租约，界面显示代理的任务结果。

```sh
p2wlan wake target add --name LabPC --mac 02:00:00:00:00:01
p2wlan wake target list
p2wlan wake target remove TARGET_ID
```

`add` 和 `list` 可用 `--network ROOM_ID` 指定已有房间网络。

## Windows 启动后自动上线

若目标需要在登录桌面前上线，选用 Windows 安装器的所有用户安装模式。先用交互应用完成设备登记，开启远程开机，然后停止该实例。在管理员 PowerShell 中从已安装的 P2WLAN 目录运行：

```powershell
.\p2wlan.exe service install --migrate-identity
.\p2wlan.exe service status
.\p2wlan.exe --config "$env:ProgramData\p2wlan\p2wlan-config.json" wake status
```

每台 Windows 主机的 P2WLAN 服务使用一份机器级配置，默认迁移个人设备身份。也可用全局 `--config` 指定一个已经登记的独立配置。服务会自动启动完整 daemon 并加载 Wintun。Windows 还需要完成启动并取得网络连接。如果 BitLocker 按策略要求预启动 PIN，需先在目标机完成解锁。

交互客户端的远程开机开关随该客户端的 daemon 重启生效。调整服务的配置时，先在管理员终端运行 `.\p2wlan.exe service uninstall` 停止服务，再对 `%ProgramData%\p2wlan\p2wlan-config.json` 使用 `--config` 保存设置，最后用原用户配置重新安装服务。

设备凭据沿用 Control 的 30 天有效期。凭据失效后，先卸载服务，用原用户配置在交互客户端登录、联网并取得新凭据，再停止该实例并重新执行 `service install --migrate-identity`。服务会更新同一设备的凭据并保留机器级设置。

## 排障

| 现象 | 检查 |
| --- | --- |
| 无可用代理 | 代理是否在同一 Control 网络、已声明代理能力且保持在线。 |
| 已发包，目标未醒 | 检查选中的代理、VLAN、网卡待机供电和电源状态。若代理是 OpenWrt，可在目标 LAN 接口用 `tcpdump -i br-lan -X 'udp port 9'` 查看本机发送的魔术包。抓包中包含目标 MAC，请留在本机。 |
| 目标已醒，客户端仍离线 | 检查 Windows 服务状态、Wintun、Control 连通性和预启动解锁。站在 Windows 登录界面时，从另一台设备确认目标的 Control 在线状态。 |
