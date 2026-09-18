# 客户端指南

## 安装与配置

优先使用 GitHub Release 的固定版本包。安装脚本只负责安装公开的客户端文件，不包含 Control 地址、账号或凭据。

## 检查客户端更新

桌面和移动客户端启动后会异步检查一次 GitHub 上的客户端正式 Release；也可以在“设置 → 诊断与关于 → 检查更新”中手动检查。客户端只接受 `vX.Y.Z` 标签，服务端的 `server-vX.Y.Z` 标签不会被当作客户端版本。

发现新版本时，客户端显示当前版本和最新版本，用户确认后打开对应的 GitHub Release 页面。更新检查失败不会阻止客户端启动，也不会自动下载、替换或安装任何程序；手动安装仍使用固定版本 Release 包。

常用 CLI：

    p2wlan config set control https://control.example.com
    p2wlan config show
    p2wlan login -u your-name
    p2wlan up
    p2wlan down
    p2wlan status

登录和配置不要使用 sudo；创建 TUN、路由或系统服务时，CLI 会在需要的位置请求权限。

Windows、macOS 和 Linux 桌面客户端可在“设置 → 通用 → 登录时启动 P2WLAN”中选择是否在当前用户进入桌面会话后自动启动应用，并在登录状态、首次配置和本机 VPN 能力均有效时连接已配置的 P2WLAN 网络。手动启动应用不会隐式连接网络。

登录自启只写入当前用户范围：Windows 使用 `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`，macOS 使用 `~/Library/LaunchAgents/io.p2wlan.desktop.login-startup.plist`，Linux 使用 XDG Autostart（`$XDG_CONFIG_HOME/autostart/p2wlan.desktop`，未设置绝对的 `XDG_CONFIG_HOME` 时回退到 `~/.config/autostart/p2wlan.desktop`）。关闭开关会移除对应当前用户条目，不创建系统级服务。

如果应用安装位置变化，设置页会把旧条目视为未启用；重新打开开关会使用当前应用路径重建条目。没有有效登录状态、首次配置未完成或当前平台不能作为本机 VPN 节点时，即使应用由登录自启启动，也不会自动启动网络。

## 路径和路由

    p2wlan doctor
    p2wlan route verify
    p2wlan route repair
    p2wlan logs -f

CLI 展示的是 daemon 已确认的状态。Connecting 不等于业务可用，Direct/Relay 标签也不等于对端应用已经收到数据；需要用虚拟 IP 执行实际的 TCP、UDP 或 ICMP 验证。

## 支持包

支持包用于用户主动提交诊断。上传前检查压缩包和日志，删除不必要的业务信息，确认接收方和保留期限。不要上传 JWT、设备凭据、Relay ticket、私钥、完整环境文件或真实主机密钥。

没有获得明确上传授权时，只保留本地文件并通过安全渠道交给管理员。支持包行为和服务端保存目录由当前实现与部署策略共同决定。
