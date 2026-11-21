# 运维指南

本指南面向自托管 P2WLAN 服务的管理员，介绍服务端运行维护、Web 管理控制台（Admin UI）使用、证书更新与排障监控等关键操作。

---

## 1. 服务生命周期管理

原生部署通过 `p2wlan-server` 管理工具统一控制后台服务：

```bash
# 查看所有组件（Control / Relay）状态
sudo p2wlan-server status --service all

# 启动、停止或重启服务
sudo p2wlan-server start --service all
sudo p2wlan-server stop --service all
sudo p2wlan-server restart --service all

# 服务健康度检查（基础连通性检查）
sudo p2wlan-server check --service all

# 深度体检（检查 systemd、Admin 凭据、日志目录权限、SQLite 完整性与证书）
sudo p2wlan-server doctor --service all
```

> [!TIP]
> 遇到异常时，优先运行 `doctor` 命令，它能自动诊断常见的目录权限配置缺失、数据库锁冲突或证书过期风险。

---

## 2. Web 管理控制台（Admin UI）

P2WLAN Control 内置了基于 Web 的管理控制台，供部署者以可视化方式监控全集群资源与连接拓扑。

### 开启与访问
1. **配置访问凭据**：在 Control 的配置文件（`control.env`）中设置 `CONTROL_ADMIN_TOKEN`（至少 32 位的强随机字符串）。未配置该变量时，`/admin` 路径默认返回 404 隐藏；
2. **安全访问**：通过配置好的 HTTPS 反向代理访问 `https://your-domain/admin/`；
3. **登录控制台**：在登录窗口中填入对应的管理员 Token 即可进入。

### 核心功能模块

#### 仪表盘（Dashboard）
提供集群运行大盘，快速掌握在线账号数、注册设备数、当前网络/房间总数，以及最近一小时内需要重点关注的异常连接。

#### 资源管理与关系拓扑（Resources & Relationships）
- **实体列表**：支持对账号、设备、网络和房间进行分页浏览、实时搜索与在线状态筛选；
- **资源关系图**：直观展示账号与设备、网络以及房间成员之间的归属关系拓扑，便于理清多用户共享网络与设备挂载情况。

#### 连接排障（Connections & Live Topology）
- **单向观测视角**：互联网中的网络链路往往具有不对称性（例如 A 发往 B 是直连，B 发往 A 走中继）。P2WLAN 的连接数据由各节点 Daemon 独立上报，分为 `A → B` 与 `B → A` 两个单向记录，真实反映端到端的双向链路状态；
- **实时连接拓扑**：在选定网络后，可一键切换为拓扑视图，绿色实线代表稳定的 P2P Direct 直连，橙色线条代表加密 Relay 中继，虚线表示过时记录；
- **连接详情与迁移时间线**：点击任意连接可查看端到端延迟（RTT）、NAT 协商结果以及历史路径迁移记录（如从 Relay 恢复为 Direct 的过程）。

#### 待关注连接（Connection Health）
系统内置规则引擎，自动从海量连接中识别出存在潜在异常的节点对，省去人工逐个排查的麻烦：
- `reporter_offline`：上报节点心跳失联；
- `stale_observation`：节点在线但链路状态长时间未刷新；
- `no_active_path`：节点处于在线状态但尚未协商出可用数据路径；
- `frequent_path_switching`：在观察窗口内 Direct 与 Relay 频繁抖动切换；
- `repeated_path_failures`：连续多次打洞或中继连接失败。

#### 历史趋势（Trends）
提供 24 小时、7 天或 30 天的小时级历史趋势分析：
- 直连率（Direct 占比）与中继率变化曲线；
- 往返延迟（RTT）的平均值与 P95 分位分布，辅助评估跨运营商或跨国链路的通信质量。

---

## 3. 日志与证书维护

### 查看服务实时日志
```bash
# 查看 Control 控制面日志
sudo p2wlan-server logs --service control

# 查看 Relay 中继面日志
sudo p2wlan-server logs --service relay
```

### Relay TLS 证书更新
Relay 服务使用标准 TLS 协议保障通信安全。证书续期流程如下：
1. 更新部署目录中引用的证书文件（通常为 `fullchain.pem` 和 `privkey.pem`）；
2. 重启 Relay 服务以加载新证书：
   ```bash
   sudo p2wlan-server restart --service relay
   ```
3. 验证外部连接与证书有效性：
   ```bash
   sudo p2wlan-server check --service relay
   ```

### 客户端诊断日志接收目录
当用户通过客户端上传诊断支持包时，Control 会将其持久化到 `LOG_UPLOAD_DIR` 指定的目录中（默认位于数据目录下的 `log-uploads`）。该目录必须由服务运行用户独占访问（权限 `0700`），避免敏感调试数据泄露。

---

## 4. 数据备份与安全准则

1. **数据库一致性快照**：
   P2WLAN Control 使用 SQLite 存储元数据。日常备份请使用系统内置的快照工具（`sudo p2wlan-server backup`），切勿在服务运行时直接复制正在写入的 `.db` 文件。
2. **密钥凭据保护**：
   `control.env` 中的 `JWT_SECRET`、`CONTROL_ADMIN_TOKEN` 与 Relay 密钥属于核心敏感凭据。请确保配置文件权限为 `0600`，且不要将这些凭据提交至公共代码仓库或公开日志中。
