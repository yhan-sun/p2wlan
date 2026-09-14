# 架构

P2WLAN 将控制面、数据面和中继分开：

- Control Plane（Go + SQLite）负责账号、设备、虚拟地址、房间、信令、凭据和 Relay catalog。
- Rust daemon 负责 TUN、路由、Peer、NAT traversal、加密会话、路径状态和 Direct/Relay 选择。
- Relay（Go）验证短期票据并转发密文，不解密业务载荷。
- Flutter 提供跨平台客户端界面；CLI 复用 daemon 的本地控制接口。

Control 的 HTTPS/WSS 只负责控制和信令，Relay 的 TLS 连接负责数据转发。服务器不会因为部署了 Control/Relay 就自动加入房间或替客户端创建 TUN。

当前数据面是自包含的 WireGuard-like Noise 实现，不是官方 WireGuard，也不声明 WireGuard 互操作兼容。实现细节以源码、协议测试和发布身份检查为准。
