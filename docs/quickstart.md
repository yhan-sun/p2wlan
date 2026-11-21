# 快速开始

通过本指南，你可以在几分钟内完成 P2WLAN 客户端的安装、配置并与朋友或自己的设备建立虚拟局域网连接。

## 1. 准备工作

P2WLAN 采用去中心化直连与集中控制协调相结合的架构。开始前，你需要一个 P2WLAN Control 服务器地址：
- 如果朋友已经搭建了服务器，直接向其索取服务器地址（如 `https://control.example.com`）；
- 如果打算自己搭建，请先参考[自托管指南](guides/self-hosting.md)在云服务器或局域网机器上完成部署。

## 2. 安装与配置客户端

前往 GitHub Releases 页面，下载适合你操作系统的客户端安装包：
- **Windows / macOS / Android**：推荐下载图形客户端，安装后即可在图形界面中直观操作；
- **Linux**：可选择图形客户端或轻量 CLI 工具。

### 图形客户端配置
打开客户端后，在登录界面填入服务器地址（例如 `https://control.example.com`），输入用户名进行登录或注册。登录成功后，客户端会自动拉取网络配置与中继信息。

### 命令行（CLI）配置
如果你使用的是 Linux 服务器或习惯使用终端，可以通过 CLI 进行配置：

```bash
# 设置服务器地址
p2wlan config set control https://control.example.com

# 登录或注册账号
p2wlan login -u your-name

# 查看当前账号信息
p2wlan account show
```

启动虚拟网络并检查状态：

```bash
# 启动网络（创建虚拟网卡并建立连接）
p2wlan up

# 查看运行状态与分配到的虚拟 IP
p2wlan status

# 运行健康检查诊断
p2wlan doctor
```

## 3. 加入房间与网络互通

P2WLAN 通过“房间”来组织互联的设备。加入同一个房间的设备就像接入了同一台虚拟交换机：

```bash
# 查看可用房间
p2wlan room list

# 加入或连接房间
p2wlan room connect <房间号或房间 ID>
```

连接成功后，在客户端或 `p2wlan status` 中可以看到对端设备的在线状态与分配到的私有虚拟 IP。

### 验证通信
通过虚拟 IP 测试两端连通性与实际应用业务：

```bash
# 测试网络连通性
ping <对端虚拟 IP>

# 测试实际业务连接（如 SSH、游戏服务或 Web 面板）
ssh <对端虚拟 IP>
```

> [!TIP]
> **关于连接路径**：
> P2WLAN 会优先尝试 **局域网直连** 与 **IPv6 / IPv4 UDP 打洞直连**（延迟最低，不消耗服务器中继流量）。当两端处于复杂的对称型 NAT 或被严格防火墙阻隔时，系统会自动平滑切换到 **端到端加密中继（Relay）** 转发，确保连接始终可用。

## 4. 常见问题与排查

如果遇到连接不通或设备离线，可以按以下顺序快速定位：

```bash
# 1. 检查客户端版本
p2wlan --version

# 2. 输出结构化状态（包含路径类型：Direct 或 Relay）
p2wlan status --json

# 3. 运行本地网络与路由诊断
p2wlan doctor

# 4. 查看实时运行日志
p2wlan logs -f
```

更详细的排查技巧与解决方案，请参阅[排障指南](guides/troubleshooting.md)。
