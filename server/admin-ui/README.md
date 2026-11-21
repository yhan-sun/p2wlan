# P2WLAN Web 管理控制台 (Admin UI)

`server/admin-ui` 是 P2WLAN Control 服务端内置的现代化 Web 运维控制台。自托管管理员无需额外搭建运维平台，即可通过浏览器直观掌控全集群的账号、设备、网络拓扑与实时连接质量。

---

## 架构与设计理念

- **零运行时依赖**：基于 React 19、TypeScript 与 Vite 开发；构建产物在服务端发布时通过 `go:embed` 直接编译进 `p2wlan-control` 单一二进制程序中。生产部署服务器**无需安装 Node.js、Nginx 额外静态配置或独立 Web 服务**；
- **只读观测与最小特权**：作为自托管管理员的专属运维面板，通过独立的 `CONTROL_ADMIN_TOKEN` 鉴权，专注于集群资源观测与链路诊断，不干预也不篡改客户端的本地网络状态；
- **现代化可视化体验**：采用 `@xyflow/react`（React Flow）与 Dagre 布局引擎构建交互式拓扑图，配合 TanStack Query 与 TanStack Table 实现平滑的响应式交互。

---

## 核心功能模块

### 1. 仪表盘（Dashboard）
- 集群总体运行状态看板：在线账号数、注册设备数、活跃网络与房间总览；
- 聚合最近 1 小时内需要重点关注的异常连接，辅助管理员第一时间察觉网络劣化。

### 2. 资源管理与关系图谱（Resources & Relationships）
- **实体清单**：对集群内的账号、挂载设备、虚拟网络与房间进行分类管理，支持关键字搜索、在线状态过滤与快照游标分页；
- **资源拓扑图（Relationships）**：基于 `@xyflow/react` 动态渲染账号、网络与设备之间的归属挂载关系，清晰呈现多用户共享网络与房间结构。

### 3. 连接排障与实时拓扑（Connections & Live Topology）
- **单向链路观测（Directional Observations）**：真实反映互联网路由的不对称特性。分别记录并展示 `A → B` 与 `B → A` 两个方向的真实路径（Direct / Relay）、协商时间与端到端延迟（RTT）；
- **实时连接拓扑（Live Topology）**：以可视化图形直观展示节点间当前使用的连接通道（绿色实线为 P2P 直连，橙色为加密中继转发，虚线为过时链路）；
- **链路迁移时间线**：点击任意节点或连接边，可调出该连接的历史迁移时间线，回溯从 Relay 切换为 Direct 直连的完整协商记录。

### 4. 待关注连接（Connection Health）
内置规则引擎，自动识别存在隐患的节点对，省去人工逐一排查：
- **`reporter_offline`**：上报端节点心跳断开；
- **`stale_observation`**：节点在线但链路信息长时间未刷新；
- **`no_active_path`**：节点处于在线状态但尚未协商出可用数据路径；
- **`frequent_path_switching`**：观察窗口内 Direct 与 Relay 频繁抖动切换；
- **`repeated_path_failures`**：连续多次打洞或中继连接失败。

### 5. 长期历史趋势（Trends）
- 提供按小时聚合的 24 小时、7 天与 30 天历史趋势大盘；
- 统计直连率与中继率变化走势，以及端到端往返延迟（RTT）的平均值与 P95 分位直方图，便于长期容量规划。

---

## 本地开发与构建

在日常开发与维护中，可以通过以下命令进行本地联调与构建验证：

```bash
cd server/admin-ui

# 安装依赖
npm ci

# 启动本地热重载开发服务器 (默认端口 http://127.0.0.1:5173)
npm run dev

# 执行 TypeScript 类型检查
npm run typecheck

# 运行自动化单元测试
npm test

# 执行生产级构建 (产物输出至对应构建目录)
npm run build
```

> [!NOTE]
> 在修改 `src/` 下的代码后，运行 `npm run build` 会重新生成静态产物。提交前请确保通过 `typecheck` 与 `test` 测试。
