# P2WLAN 技术调研笔记

Version: 0.1  
Date: 2026-07-16

## 1. 可行性判断

这个项目可行，但难度较高。工业界已有多条相似路线证明架构成立：

- Tailscale：WireGuard 数据面、NAT traversal、DERP/Peer Relay fallback。
- NetBird：WireGuard、Management、Signal、Relay、ICE/STUN/TURN。
- ZeroTier：自研虚拟网络和 overlay。
- libp2p：AutoNAT、Circuit Relay、DCUtR hole punching。
- frp：端口映射、反向代理和公网入口。

P2WLAN 的合理定位是先做私有化、可控、开发者友好的 P2P 虚拟内网，而不是第一天就挑战全球级商用网络。

## 2. 参考项目对比

| 项目 | 可借鉴点 | 不直接复制的原因 |
| --- | --- | --- |
| Tailscale | WireGuard + NAT traversal + DERP fallback + MagicDNS | 控制面商业化较深，完整行为复杂 |
| NetBird | Management/Signal/Relay 分层清晰，ICE/STUN/WireGuard 组合接近目标 | Go 生态为主，客户端架构需结合 Rust 目标重设 |
| ZeroTier | 虚拟网络抽象和多平台经验 | 自研协议复杂，学习成本高 |
| libp2p | NAT traversal、relay、连接升级思想 | 目标是通用 P2P 栈，不是虚拟网卡 VPN |
| WireGuard | 高性能加密隧道和 cryptokey routing | 不提供节点发现、控制面、Relay、NAT traversal |
| frp | 端口映射和公网反向隧道体验 | 不解决虚拟内网和设备间 L3 overlay |

## 3. 推荐技术组合

### 第一阶段推荐

```text
Rust daemon
  -> Linux TUN
  -> user-space WireGuard
  -> UDP transport
  -> manual peer config
```

原因：最短路径验证虚拟网卡、加密隧道和虚拟 IP 互通。

### 第二阶段推荐

```text
Go control server
  -> device registry
  -> network map
  -> signaling stream

Rust daemon
  -> STUN
  -> candidate gather
  -> UDP hole punching
```

原因：把手工 peer 配置替换成自动发现和自动连接。

### 第三阶段推荐

```text
Relay server
  -> authenticated sessions
  -> encrypted packet forwarding
  -> region selection
  -> direct path reprobe
```

原因：没有 Relay 的 P2P 网络在真实用户网络中体验不稳定。

## 4. 关键工程取舍

### Rust 客户端 vs Go 客户端

Rust 更符合低内存、系统 API、跨平台 daemon 的目标。Go 更适合快速实现网络服务端。客户端核心建议 Rust，控制面建议 Go。

### WireGuard vs 自研加密协议

应选择 WireGuard。自研加密协议风险极高，且项目核心难点不是加密算法，而是虚拟网卡、NAT traversal、控制面、Relay、策略和跨平台体验。

### 完整 ICE vs ICE-inspired

完整 ICE 规范复杂。MVP 可以先实现候选收集、信令交换、并发 probe 和路径选择。等核心链路稳定后，再评估是否引入成熟 ICE 库或补齐 trickle ICE、TURN 兼容等能力。

### Relay over TCP/WebSocket vs UDP/QUIC

MVP 可以使用 TLS WebSocket 或 TCP stream 作为 Relay transport，优点是企业网络穿透能力强、实现简单。长期性能优化可增加 UDP/QUIC Relay。

### macOS utun vs Network Extension

开发阶段 utun 简单直接。正式产品如果需要稳定分发和系统 VPN 体验，应使用 Network Extension 的 Packet Tunnel Provider，但需要 Apple entitlement。

## 5. 最小可行产品

真正的 MVP 不是 UI，而是以下闭环：

```text
两台 Linux 机器
  -> 注册到控制面
  -> 获取虚拟 IP
  -> 自动发现 peer
  -> 建立 WireGuard tunnel
  -> ping/ssh/curl 通过虚拟 IP 成功
  -> direct 失败时 Relay 成功
```

只要这个闭环跑通，后续 DNS、ACL、端口映射、UI 都是可迭代增强。

## 6. 推荐阅读顺序

1. WireGuard whitepaper：理解数据面和 cryptokey routing。
2. Tailscale connection types 和 DERP：理解 direct/relay 的产品化路径。
3. NetBird 架构：理解 Management/Signal/Relay 分层。
4. Linux TUN/TAP、Wintun、Apple Network Extension：理解虚拟网卡平台差异。
5. RFC 8445 ICE 和 RFC 8489 STUN：理解 NAT traversal 标准术语。
6. libp2p DCUtR 和 Circuit Relay：理解通过 Relay 升级到 direct path 的思路。
7. 大规模 NAT traversal 测量研究：理解真实网络里 hole punching 成功率不是 100%，Relay fallback 是产品可用性的必要条件。

## 7. 参考链接

- [Tailscale connection types](https://tailscale.com/docs/reference/connection-types)
- [Tailscale peer relays](https://tailscale.com/docs/features/peer-relay)
- [Tailscale DERP Go package](https://pkg.go.dev/tailscale.com/derp)
- [Tailscale derper README](https://github.com/tailscale/tailscale/blob/main/cmd/derper/README.md)
- [NetBird: How NetBird Works](https://docs.netbird.io/about-netbird/how-netbird-works)
- [NetBird NAT and connectivity](https://docs.netbird.io/about-netbird/understanding-nat-and-connectivity)
- [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [Wintun](https://www.wintun.net/)
- [Linux Universal TUN/TAP driver](https://docs.kernel.org/next/networking/tuntap.html)
- [Apple NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
- [RFC 8445: ICE](https://www.rfc-editor.org/rfc/rfc8445)
- [RFC 8489: STUN](https://www.rfc-editor.org/rfc/rfc8489)
- [libp2p DCUtR](https://libp2p.io/docs/dcutr/)
- [libp2p AutoNAT](https://docs.libp2p.io/concepts/nat/autonat/)
- [libp2p Circuit Relay](https://docs.libp2p.io/concepts/circuit-relay/)
- [Large-Scale Measurement of NAT Traversal for the Decentralized Web](https://arxiv.org/abs/2604.12484)
