# 配置参考

## Control

| 变量 | 规则 |
| --- | --- |
| CONTROL_BIND / PORT | CONTROL_BIND 优先；内部监听使用 host:port。 |
| DB_PATH | SQLite 文件路径，不是目录；相对路径相对于服务工作目录。 |
| JWT_SECRET | 每个部署独立随机值，持续保存；改变会使现有账号会话失效。 |
| CONTROL_ADMIN_TOKEN | 可选的管理控制台凭据；为空时 `/admin` 与 `/admin/*` 返回 404。启用时至少 32 个字符，只用于 `/admin/api/v1/*` 的 Bearer 认证，不能复用 JWT_SECRET 或 Relay 凭据。 |
| LOG_UPLOAD_DIR | 支持日志保存目录，必须是受保护的持久目录。 |
| RELAY_CATALOG_JSON | 每项包含唯一 region、audience 和客户端可访问的 tls:// endpoint。 |
| RELAY_TICKET_SIGNER_KEY_FILE / RELAY_TICKET_SIGNER_KID | 签票私钥和 key id，必须成对配置。 |
| RELAY_TICKET_TTL | Relay ticket 的短期有效期，不是账号 token 的有效期。 |
| RELAY_REVOCATION_FEED_TOKEN | Control 与 Relay 之间独立的撤权凭据。 |

`CONTROL_ADMIN_TOKEN` 只开启同一 Control origin 下的只读管理台。管理页不会把令牌写回响应，也不会把用户 JWT 提升为全局管理员权限；公网访问时仍必须由可信 HTTPS 反向代理保护 Control。

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
