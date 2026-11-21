# 系统架构

P2WLAN 采用控制面、数据面、中继面与呈现面解耦的系统架构，既保障了 P2P 直连的高性能与低延迟，又具备集中化管理的便捷性与中继兜底的高可用性。

```mermaid
flowchart TD
    subgraph ClientA["客户端 A (终端设备)"]
        UI_A["Flutter App / CLI"]
        Daemon_A["Rust Daemon (网卡/加密/打洞)"]
        UI_A <-->|本地 IPC| Daemon_A
    end

    subgraph ClientB["客户端 B (终端设备)"]
        UI_B["Flutter App / CLI"]
        Daemon_B["Rust Daemon (网卡/加密/打洞)"]
        UI_B <-->|本地 IPC| Daemon_B
    end

    subgraph Server["P2WLAN 服务端"]
        Control["Control 控制面 (Go + SQLite)"]
        AdminUI["Admin UI 运维控制台 (内嵌 Web)"]
        Relay["Relay 中继服务 (Go)"]
        AdminUI <-->|HTTP API| Control
        Control <-->|撤权流与票据鉴权| Relay
    end

    Daemon_A <-->|HTTPS/WSS 控制与信令| Control
    Daemon_B <-->|HTTPS/WSS 控制与信令| Control

    Daemon_A <===>|优先: P2P 直连 (UDP/IPv6)| Daemon_B
    Daemon_A -.->|兜底: 加密中继| Relay
    Relay -.->|兜底: 加密中继| Daemon_B
```

## 核心组件与分工

### 1. 客户端网络核心（Rust Daemon）
Rust Daemon 是运行在客户端本地的网络引擎，拥有本地网络状态与数据面的完整控制权：
- **虚拟网络适配器（TUN）**：负责在各操作系统（Windows Wintun、macOS utun、Linux tun、Android VpnService）上创建虚拟网卡并配置路由；
- **加密通道**：基于 Noise 协议框架实现类似 WireGuard 的点对点端到端加密会话；
- **智能 NAT 穿透**：集成 STUN 探测、端口预测、生日探测以及双对称 NAT 协调打洞（HH2）；
- **动态路径决策**：默认采用 Direct-first 策略，优先建立 P2P 直连通道；在打洞未完成或网络受阻时，无缝切换到加密 Relay 中继；
- **路径可观测性**：将本地观测到的真实连接路径（Direct/Relay）、延迟（RTT）与迁移事件，单向异步上报至控制面。

### 2. 跨平台客户端应用（Flutter Client）
Flutter 客户端是面向终端用户的统一产品界面，覆盖 Windows、macOS、Linux 与 Android：
- 提供直观易用的设备连接、状态展示与房间管理界面；
- 负责用户登录、网络配置保存与本地 Daemon 进程的生命周期管理；
- 提供内置的网络连通性检查与一键诊断工具。

### 3. 服务端控制面（Control Plane）
Control 服务端基于 Go 与 SQLite 构建，负责协调整个虚拟局域网的元数据与控制逻辑：
- **账号与设备认证**：管理用户身份、设备登记与短期访问凭据；
- **房间与信令中枢**：维护房间成员列表，在节点间安全投递 NAT 协商与打洞信令；
- **中继调度**：向客户端签发短期中继访问票据（Ticket）；
- **连接数据持久化**：汇聚并持久化各客户端上报的权威连接快照与历史趋势，为运维排障提供只读数据支撑。

### 4. 服务端中继（Relay Plane）
Relay 独立运行或与 Control 协同部署，是 P2P 直连无法建立时的通信兜底基座：
- 仅负责基于短期票据鉴权的数据包中继转发；
- 实行**端到端加密零知识转发**：中继服务器仅能看到密文、数据包大小和会话元数据，完全无法接触或解密任何用户业务载荷；
- 支持与 Control 保持实时撤权同步，及时切断失效设备的网络接入。

### 5. 后台运维 Web 控制台（Admin UI）
位于 `server/admin-ui` 的后台管理界面是面向自托管运维人员的可视化控制台：
- 技术栈基于 React、TypeScript 与 Vite 开发；静态产物在发布构建时通过 `go:embed` 直接编译进 `p2wlan-control` 单一可执行文件中，零额外运行时依赖；
- 部署者通过浏览器访问 `https://your-domain/admin/`，使用独立的管理员凭据即可查看全集群状态。

---

## 客户端 App 与 后台 Web 的产品定位

P2WLAN 清晰划分了面向普通使用者的**客户端 App**与面向自托管管理员的**后台 Web 控制台**，避免职责混淆：

| 维度 | 客户端 App (Flutter) | 后台 Web 控制台 (Admin UI) |
| --- | --- | --- |
| **主要受众** | 终端用户、联机玩家、远程办公者 | 自托管服务部署者、系统管理员 |
| **运行位置** | 用户本地设备（PC / 手机） | 服务端内嵌（通过浏览器访问） |
| **核心职责** | 掌管本地虚拟网卡、网络加解密、房间出入与网络控制 | 观察集群资源全貌、查看节点连接状态与排查全局网络质量 |
| **操作权限** | 具备本机网络控制权（创建网卡、配置路由、发起连接） | 只读观测控制台（不干预单机网卡，不伪造网络状态） |
| **数据视角** | 本机与对端直接交互的第一视角 | 服务端收集到的全局拓扑与单向遥测汇总视角 |

两套界面相辅相成：用户通过客户端 App 轻松享受顺畅的组网体验，而管理员则通过 Web 控制台实时了解网络运行质量与潜在瓶颈。
