# 兼容性参考

本篇文档列出 P2WLAN 各组件支持的操作系统、架构、运行环境要求及版本兼容规范。

---

## 1. 客户端支持矩阵

| 平台 | 架构 | 发布形式 | 最低系统版本 | 权限与依赖说明 |
| --- | --- | --- | --- | --- |
| **Windows** | x64 | 安装程序 (`.exe`) | Windows 10 (1809+) / 11 | 需要管理员权限安装 Wintun 驱动 |
| **macOS** | Apple Silicon / Intel | 磁盘映像 (`.dmg`) | macOS 12 (Monterey)+ | 首次启动网络需要系统管理员授权以创建 utun 接口 |
| **Linux (桌面)** | x64 / arm64 | 便携包 / 安装包 | 主流发行版（Ubuntu 22.04+、Debian 12+、Fedora 等） | 需要 TUN 模块（`kmod-tun`）及 PolicyKit/sudo 授权 |
| **Linux (CLI)** | x64 / arm64 | 独立压缩包 (`tar.gz`) | glibc 2.31+ | 适合服务器与无桌面环境 |
| **OpenWrt** | ARM64 / x86_64 | 原生包 (`.ipk` / `.apk`) | OpenWrt 24.10 / 25.12 | 详情请参考 [OpenWrt 路由器指南](../guides/openwrt.md) |
| **Android** | arm64-v8a | 安装包 (`.apk`) | Android 7.0 (API 24)+ | 需要在系统中授予 VPN 连接权限 |

> [!NOTE]
> iOS 客户端目前尚在开发与测试阶段，暂未发布正式安装包。

---

## 2. 服务端支持与运行环境

P2WLAN 服务端（Control 与 Relay）采用 Go 语言开发，支持以下运行形态：

- **Docker 容器部署（推荐）**：支持 Linux x86_64 与 ARM64，兼容主流 Linux 发行版（Ubuntu、Debian、CentOS、Rocky、Alpine 等）；
- **Linux 原生 systemd 部署**：提供静态编译的无动态链接二进制包，经过 Ubuntu 22.04 LTS / 24.04 LTS、Debian 12 等环境的完整测试；
- **自托管部署指南**：完整安装、反向代理与证书设置请参阅[自托管指南](../guides/self-hosting.md)。

---

## 3. 版本命名规范与兼容性

为了清晰区分客户端与服务端的发布节奏，项目采用了独立的版本标签命名空间：

- **客户端版本**：以 `vX.Y.Z` 命名（例如 `v0.1.170`）；
- **服务端版本**：以 `server-vX.Y.Z` 命名（例如 `server-v0.1.170`）。

### 双对称 NAT 穿透协商（HH2）
新版本客户端引入了 HH2 增强穿透协调协议，支持在复杂的双对称 NAT 下进行端口预测与协同探测：
- 当通信双方均支持 HH2 时，系统自动启用高级协同穿透方案；
- 若其中一方为旧版本，系统会自动回退到经典打洞流程或透明 Relay 中继，确保连接平稳兼容。
