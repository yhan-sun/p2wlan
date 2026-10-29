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
| RELAY_TICKET_SIGNER_KEY_FILE / RELAY_TICKET_SIGNER_KID | Control 的 Ed25519 PKCS#8 PEM 签票私钥文件和 key id，必须成对配置；私钥不分发给 Relay。 |
| RELAY_TICKET_SIGNER_JSON | 内联签名配置；生成器使用 `{"active":{"kid":"…","private_key":"…"}}`，其中私钥值为十六进制 seed。与文件方式选择一种；此值按私钥保护。 |
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
| RELAY_TICKET_KEYRING_JSON | 非空 JSON 对象，形如 `{"key-id":"<64 位十六进制 Ed25519 公钥>"}`；key id 和公钥必须对应 Control 的签名配置，不填写私钥、JWT_SECRET 或 TLS 证书。 |
| RELAY_AUDIENCE / RELAY_REGION | 必须与 Control catalog 的一项完全匹配。 |
| RELAY_REVOCATION_FEED_URL | 分机部署使用 HTTPS；同机可用受保护的 loopback 路径。 |
| RELAY_REVOCATION_FEED_TOKEN | 必须与 Control 完全相同，但不能复用 JWT_SECRET。 |
| RELAY_METRICS_BIND | 只绑定 127.0.0.1 或 IPv6 loopback。 |
| RELAY_REQUIRE_AUTH | 生产保持 true。 |
| RELAY_ALLOW_LEGACY_UNAUTH | 生产保持 false。 |
| RELAY_ALLOW_INSECURE_PLAINTEXT | 生产禁止。 |

配置生成器会检查目录、证书、签票关系和随机秘密。正式启动还必须拒绝占位符、弱默认值和缺失证书。

`p2wlan-config --print-relay-keyring` 读取现有 `RELAY_TICKET_SIGNER_*` 环境配置，输出对应的公钥 JSON，不生成或替换密钥。全新同机安装和已有配置恢复步骤见[自托管指南](../guides/self-hosting.md#relay-配置缺失时恢复)。Relay 配置缺失时须补齐配置，保持认证与 TLS 启用。

## 客户端资源观测

客户端软件缓冲观测由 `diagnostics.resource_capture` 控制，缺省为 `false`。只有它与 `diagnostics.enabled` 同为 `true` 时，daemon 才为本次进程建立观测。CLI 可设置并保存：

    p2wlan config set resource-capture true

该命令同时启用本地诊断；重新启动对应 daemon 后生效。读取使用 `p2wlan status --resources`，经原有实例诊断令牌访问 `GET /resources`。关闭使用 `p2wlan config set resource-capture false` 后重启，不会关闭其他诊断。资源观测的单位、不可用状态和覆盖限制见[路径可观测性](path-observability.md#软件缓冲资源观测)。

## 客户端路径策略

`relay.path_policy` 缺省值为 `direct-first`。首次在线 peer 生命周期保留 5 秒直连窗口；健康的加密确认 Direct 保持优先。Relay 可提前建立和认证，但窗口到期前不承载本端首个业务包。确认 Direct 失活后立即允许已认证 Relay 兜底，不为已建立连接重跑冷启动等待。

    p2wlan config set path-policy direct-first

配置保存后重新启动对应 daemon/profile 生效。旧配置中显式保存的 `auto`、`score`、`direct-sticky`、`relay-only` 不会被悄悄迁移；需要直连优先时显式设置上述值。`auto` 保留旧的立即 Relay 回退策略，`score` 比较已确认路径质量，`direct-sticky` 只保证已确认 Direct 的保持，`relay-only` 明确禁用 Direct 业务路径。`prefer_direct=false` 仍具有 Relay-only 语义。

Relay-only 启动时不解析 Direct 专用的 STUN 或 UDP observer 地址，也不启动 Direct 探测和 UDP 连接任务；Control、Relay 与 WireGuard 会话维护仍正常运行。其他路径策略保留 Direct 升级能力。

`relay_startup_timeout_ms` 仍默认为 3000，旧字段 `fallback_timeout_ms` 仍是读取别名。在 Direct-first 下，首次业务 FIFO 的总等待预算包含 5 秒直连窗口，再加配置的 Relay 启动等待；未配置 Relay 时只等待 Direct，不会虚构中继。该预算不会因每个新业务包或候选刷新而无限续期；队列仍受原有包数、字节数和 generation 边界保护。

CLI 的 `--prefer-direct` 与 `relay-policy=direct` 选择 Direct-first；显式 `--prefer-relay` 或 `relay-policy=prefer-relay` 使用兼容 Auto，不等同于 Relay-only。
