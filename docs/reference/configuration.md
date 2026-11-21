# 配置参考

## Control

| 变量 | 规则 |
| --- | --- |
| CONTROL_BIND / PORT | CONTROL_BIND 优先；内部监听使用 host:port。 |
| DB_PATH | SQLite 文件路径，不是目录；相对路径相对于服务工作目录。 |
| JWT_SECRET | 每个部署独立随机值，持续保存；改变会使现有账号会话失效。 |
| CONTROL_ADMIN_TOKEN | 管理控制台凭据；`p2wlan-config` 默认生成独立 256-bit 随机值。为空时 `/admin` 与 `/admin/*` 返回 404；手工配置时至少 32 个字符，只用于 `/admin/api/v1/*` 的 Bearer 认证，不能复用 JWT_SECRET 或 Relay 凭据。 |
| LOG_UPLOAD_DIR | 支持日志保存目录。托管部署显式配置为服务账户可写的绝对持久路径；默认受管理目录为数据目录下的 `log-uploads`，权限 `0700`。升级保留非空自定义值。 |
| RELAY_CATALOG_JSON | 每项包含唯一 region、audience 和客户端可访问的 tls:// endpoint。 |
| RELAY_TICKET_SIGNER_KEY_FILE / RELAY_TICKET_SIGNER_KID | 签票私钥和 key id，必须成对配置。 |
| RELAY_TICKET_TTL | Relay ticket 的短期有效期，不是账号 token 的有效期。 |
| RELAY_REVOCATION_FEED_TOKEN | Control 与 Relay 之间独立的撤权凭据。 |

未配置或留空 `LOG_UPLOAD_DIR` 时，Control 在 `DB_PATH` 为绝对路径的情况下使用数据库父目录下的 `log-uploads`；`DB_PATH` 缺失或为相对路径时，兼容默认仍为进程工作目录下的 `data/log-uploads`。固定归档的 manager 使用显式绝对路径，避免旧服务缺少工作目录配置时把支持包存到其他位置。该回退不接管不可写目录，也不改变已配置的日志路径。

`CONTROL_ADMIN_TOKEN` 只开启同一 Control origin 下的只读管理台及 Admin API（包括 `/admin/api/v1/connections`、`/admin/api/v1/connection-transitions`、`/admin/api/v1/connection-health` 与 `/admin/api/v1/connection-trends`）。管理页不会把令牌写回响应，也不会把用户 JWT 提升为全局管理员权限；公网访问时仍必须由可信 HTTPS 反向代理保护 Control。`p2wlan-config` 与固定服务端归档的 `p2wlan-server init` 都会为新部署生成独立随机值并只写入私有 `control.env`；早期缺少该项的部署可显式运行 `p2wlan-server setup` 补齐，而不会轮换已有 JWT / Relay / TLS 凭据。删除该变量并重启 Control 即可关闭管理台。

Control 信令服务在 WebSocket `ready` 帧中向客户端声明 `path_telemetry_v1` 能力；客户端同样支持该能力时，启用基于信令长连接的路径遥测通道（并在不可用时自动降级为 HTTP POST `/api/v1/telemetry/paths`）。

## Relay

| 变量 | 规则 |
| --- | --- |
| RELAY_BIND | Relay TLS 数据入口。 |
| RELAY_TLS_CERT / RELAY_TLS_KEY | 匹配的完整证书链和私钥。 |
| RELAY_TICKET_KEYRING_JSON | key id 到 32 字节公钥的映射。 |
| RELAY_AUDIENCE / RELAY_REGION | 必须与 Control catalog 的一项完全匹配。 |
| RELAY_REVOCATION_FEED_URL | 分机部署使用 HTTPS；同机可用受保护的 loopback 路径。 |
| RELAY_REVOCATION_FEED_TOKEN | 必须与 Control 完全相同，但不能复用 JWT_SECRET。 |
| RELAY_METRICS_BIND | 只绑定 127.0.0.1 或 IPv6 loopback。 |
| RELAY_REQUIRE_AUTH | 生产保持 true。 |
| RELAY_ALLOW_LEGACY_UNAUTH | 生产保持 false。 |
| RELAY_ALLOW_INSECURE_PLAINTEXT | 生产禁止。 |

配置生成器会检查目录、证书、签票关系和随机秘密。正式启动还必须拒绝占位符、弱默认值和缺失证书。

## 客户端资源观测

客户端软件缓冲观测由 `diagnostics.resource_capture` 控制，缺省为 `false`。只有它与 `diagnostics.enabled` 同为 `true` 时，daemon 才为本次进程建立观测。CLI 可设置并保存：

    p2wlan config set resource-capture true

该命令同时启用本地诊断；重新启动对应 daemon 后生效。读取使用 `p2wlan status --resources`，经原有实例诊断令牌访问 `GET /resources`。关闭使用 `p2wlan config set resource-capture false` 后重启，不会关闭其他诊断。资源观测的单位、不可用状态和覆盖限制见[路径可观测性](path-observability.md#软件缓冲资源观测)。

## 客户端路径策略

新生成的配置使用 `relay.path_policy=direct-sticky`。对端确认加密 Relay 后即可承载首包。双方协商紧凑探测时，同一 UDP 地址和本地 socket 须连续返回两个独立挑战，随后由 WireGuard 验证直连。已确认的健康 Direct 保持优先，失活后可回到已确认的 Relay。

旧配置省略 `path_policy` 时仍按 `direct-first` 读取，所有显式保存的策略继续生效。要为首次在线 peer 保留 5 秒直连窗口，可运行以下命令后重启 daemon。

    p2wlan config set path-policy direct-first

`auto` 允许立即 Relay 回退，`score` 比较已确认路径质量，`relay-only` 只使用 Relay 业务路径。`prefer_direct=false` 同样只允许 Relay。

Relay-only 启动时不解析 Direct 专用的 STUN 或 UDP observer 地址，也不启动 Direct 探测和 UDP 连接任务；Control、Relay 与 WireGuard 会话维护仍正常运行。其他路径策略保留 Direct 升级能力。

`relay_startup_timeout_ms` 仍默认为 3000，旧字段 `fallback_timeout_ms` 仍是读取别名。在 Direct-first 下，首次业务 FIFO 的总等待预算包含 5 秒直连窗口，再加配置的 Relay 启动等待；未配置 Relay 时只等待 Direct，不会虚构中继。该预算不会因每个新业务包或候选刷新而无限续期；队列仍受原有包数、字节数和 generation 边界保护。

CLI 的 `--prefer-direct` 与 `relay-policy=direct` 选择 Direct-first；显式 `--prefer-relay` 或 `relay-policy=prefer-relay` 使用兼容 Auto，不等同于 Relay-only。

### 对端协商的 UDP 探测

这些字段位于客户端配置的 `network` 对象中。也可用短横线形式通过 CLI 设置，例如 `p2wlan config set max-punch-pps 80`。两端通过带版本和期限的候选信令交换 NAT 画像，旧客户端继续使用原有候选协议。网关已映射地址优先；随机映射保留最近一次有效观察的端口。每轮 20 秒，整个尝试最长 120 秒；候选、身份或网络失效会提前结束。发包使用协商的具体地址，也可反向确认发布过的 IP 上收到的认证请求来源。

| 配置项 | 默认值 | 作用 |
| --- | --- | --- |
| `disable_sym_hole_punching` | `false` | 开启后跳过双方均为对称映射的协商探测。 |
| `lazy_p2p` | `false` | 等到 peer 有业务流量后才启动协商探测。 |
| `max_punch_pps` | `200` | 紧凑探测包每秒上限，封顶 200；设为 0 可停用。 |
| `max_punch_sockets` | `24` | 限制从已有 socket 池参与的数量，封顶 30。主 socket 可单独工作。 |
| `linear_scan_count` | `50` | 首次按步长排序时最多尝试的已发布候选数。 |
| `firewall_probe_addresses` | `[]` | 配置具有 STUN Binding 服务的固定 IP 和端口。与已配置的 UDP observer、STUN 服务器合计最多使用 8 个地址。 |

`p2wlan doctor` 显示两端 NAT 画像、队列长度、近期实际发包量及路径成本。UDP 可达性为 `unknown`、`available` 或 `blocked`。一轮内所有已完成的观察点探测都失败时会记录 `UDP_BLOCKED` 并停止当前尝试。没有配置观察点时保留 `unknown`。

### 网络实验开关

| 配置 | 生效条件 |
| --- | --- |
| `network.early_candidate_signaling` | 默认关闭。开启后，已绑定 socket 的全局 IPv6 Host 或首个有效公网 STUN 映射可进入首轮信令。后续发送完整候选集。接收端仅对同一身份、同一进程代际且保留全部原地址和来源的增量延续检查。 |
| `relay.path_policy=adaptive` | 用 `p2wlan config set path-policy adaptive` 设置。已存在待发业务、当前 Relay 写入者在线并完成对端确认，且 Direct 至少 750 ms 没有新的成功进展时，可提前承载首包。正在加密验证的 Direct 保留原始窗口，后台仍可升级直连。 |
| `network.accelerated_consent` | 默认关闭。选中的同一路径连续两次未回复保活时，可追加一次有独立 nonce 和超时的验证。第三次真实失约才触发降级。在同一会话和本地 socket 上，已认证业务的来源端口发生变化时，可继续使用原直连，同时对新端口发起加密验证。只有原路径、会话、本地 socket、验证所有者和请求编号仍匹配，才切换业务。同 IP 上的应答端口可以与请求端口不同，但新应答来源必须已独立验证。来源端口变化触发的验证对每个对端最多每 8 秒发起一次。冷却期内多次换端口时，仅保留最近的已认证来源，冷却结束后须从该端口再次收到已认证流量才能发起验证。稳定的非对称收发端口不会重复触发。 |
| `relay.warm_failover` | 默认关闭。配置多个认证中继时，主连接断开后可接管另一条仍持有有效票据的已注册连接。备用中继承载业务前，双方须在新连接完成加密确认。 |
| `RELAY_UDP_OBSERVER_ALTERNATE_BIND` | Relay 管理员可搭配 `RELAY_UDP_OBSERVER_BIND` 绑定同族、异 IP 和异端口的本机地址。客户端对主地址发送 CHANGE-REQUEST，备用地址回包。目录项设置 `udp_observer_change_ip=true` 并填写 `udp_observer_endpoint` 后，客户端优先尝试该观察点。 |

本地诊断中的 `failure_kind` 区分 STUN 观察点超时、本机 I/O 失败、无效回复、缺少映射和地址族错误。仅观察点失联时，NAT 画像保留 `unknown`。两条路径均已验通时，`quality_policy_preview` 提供现有 Score 策略在该次快照中的选路和原因。Linux 和 macOS 的桌面路由监测还会在系统睡眠至少两秒后重新验证连接。
