# 兼容性参考

| 平台 | 当前发布形态 | 说明 |
| --- | --- | --- |
| macOS 12+ Apple Silicon | DMG | 需要系统网络扩展/TUN 权限 |
| macOS 12+ Intel | DMG | 需要系统网络扩展/TUN 权限 |
| Windows x64 | 安装器 | 需要 Wintun、路由和防火墙权限 |
| Linux x64 | GUI、CLI/daemon 包 | CLI/daemon 适合无桌面服务 |
| Linux arm64 | CLI/daemon 包 | 以对应 Release 归档为准 |
| Android 7.0+ arm64 | arm64 APK | 受系统 VPN、生命周期和后台策略影响 |
| iOS 15+ arm64 | unsigned IPA | 需要用户自己的签名与系统配置，属于实验性支持 |

客户端和服务端使用独立的版本命名空间：客户端是 `vX.Y.Z`，服务端是 `server-vX.Y.Z`。即使两个标签具有相同的数字后缀，也不表示它们指向同一个源码提交、同一次构建或同一组发布产物。自托管部署和问题定位应分别记录客户端 tag + commit、服务端 tag + commit，不能只记录 `X.Y.Z`。

不同标签不代表协议完全兼容；升级前检查发布契约和服务端说明。固定服务端归档的公开部署路径、发行版验证范围和 Windows/Docker 边界见[自托管指南](../guides/self-hosting.md)。

兼容性声明只覆盖仓库已执行的构建与测试。真实设备、真实 TUN、不同 NAT、休眠唤醒、网络切换和长期业务流量需要单独验证。
