# 架构

P2WLAN 将控制面、数据面和中继分开：

- Control Plane（Go + SQLite）负责账号、设备、虚拟地址、房间、信令、凭据和 Relay catalog。
- Rust daemon 负责 TUN、路由、Peer、NAT traversal、加密会话、路径状态和 Direct/Relay 选择。
- Relay（Go）验证短期票据并转发密文，不解密业务载荷。
- Flutter 提供面向终端用户的跨平台客户端界面；CLI 复用 daemon 的本地控制接口。新的终端用户功能和 daemon↔客户端交互仍以 Flutter 客户端为产品入口。
- `server/admin-ui` 是面向自托管服务管理员的只读 Control 运维界面，生命周期、权限和数据契约都属于服务端。它使用 React/TypeScript/Vite 开发，但 production 静态产物由 Go 嵌入 `p2wlan-control`，不替代 Flutter 客户端，也不向普通账号提供客户端能力。

Control 的 HTTPS/WSS 只负责控制和信令，Relay 的 TLS 连接负责数据转发。服务器不会因为部署了 Control/Relay 就自动加入房间或替客户端创建 TUN。

管理台只展示 Control 能直接确认的服务端事实。账号、membership、设备挂载和待处理 signaling 可以组成控制面拓扑；daemon 当前选择的 Direct/Relay 数据路径仍由 daemon 拥有，Control 未持久化的状态不会由管理台根据 RTT、候选或在线标记推断出来。

当前数据面是自包含的 WireGuard-like Noise 实现，不是官方 WireGuard，也不声明 WireGuard 互操作兼容。实现细节以源码、协议测试和发布身份检查为准。
