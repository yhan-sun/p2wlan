# 快速开始

## 前提

准备一台已经提供 Control 地址的服务，或先完成[自托管部署](guides/self-hosting.md)。新安装不预填项目服务器，也不会自动注册。

## 客户端

从 GitHub Releases 下载对应平台的包并安装。Linux CLI 的远程安装器必须显式指定 `vX.Y.Z`；也可以直接使用 Release 内的固定版本包。

先写入 Control 地址，再登录：

    p2wlan config set control https://control.example.com
    p2wlan login -u your-name
    p2wlan account show

启动并确认本机网络：

    p2wlan up
    p2wlan status
    p2wlan doctor

## 房间与业务

加入房间后等待对端在线：

    p2wlan room list
    p2wlan room connect <房间号或房间 ID>

使用对端的虚拟 IP 验证实际业务，而不是只看 Control 登录成功：

    ping <对端虚拟 IP>
    ssh <对端虚拟 IP>

路径优先级是 LAN Direct、Public UDP Direct、Encrypted Relay。Direct 受 NAT、防火墙和云安全组影响；Relay 可用也依赖 Control 和 Relay 的 TLS 配置。

## 出现问题时

先保存版本和不含秘密的诊断摘要：

    p2wlan --version
    p2wlan status --json
    p2wlan doctor
    p2wlan logs -f

支持包上传不是初始化步骤。只有在确认目标、内容和保存期限后，才显式执行 support-bundle 的上传选项。详见[排障指南](guides/troubleshooting.md)。
