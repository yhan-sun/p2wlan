# 客户端指南

OpenWrt 使用原生 IPK/APK 和 procd 服务，安装、路径与升级规则见 [OpenWrt 指南](openwrt.md)。普通 Linux 的 CLI tarball 使用 glibc，不能用于 OpenWrt。

## 安装与配置

优先使用 GitHub Release 的固定版本包。安装脚本只负责安装公开的客户端文件，不包含 Control 地址、账号或凭据。

桌面和移动客户端必须在登录页填写服务器地址并登录后使用。服务器地址为必填项，中继配置由服务器自动下发；客户端不提供离线启动入口，缺少地址或登录凭据时会提示补齐配置并拒绝启动本机网络。旧配置中的离线标记不再生效，无登录凭据时进入登录页。

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

macOS 和 Linux 桌面启动会先准备当前实例的配置、日志目录，再写入一次性启动凭据。默认用户目录中遗留的 root 属主会在停止旧实例后进行有界提权恢复，每个失败目录最多恢复一次，并由当前用户复验。恢复保留配置内容，只处理本应用当前实例的目录和固定文件；自定义路径、其他用户属主、符号链接、硬链接或仍被活动实例锁定的目录会拒绝自动接管。日志轮转和 PID 文件写入由交互用户执行，Unix 配置及诊断文件保持 `0600`，运行目录保持 `0700`。

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
