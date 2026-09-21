# 安全模型

## 身份与凭据

设备控制面身份、数据面会话密钥、Relay ticket、JWT、管理控制台令牌、Relay 票据签名 key、撤权 feed token 和 TLS 私钥承担不同职责，不能互相替代。管理控制台令牌只授权同一 Control 实例的只读管理 API，不授予设备身份、房间成员身份或 Relay 数据连接权限。ticket 必须绑定 audience、region、设备/网络身份和短期过期时间；Relay 在撤权 feed 未就绪或过期时拒绝新的认证连接。

## 数据面

业务数据在端点之间使用加密会话。Relay 看到节点标识、时间、连接频率和包大小等元数据，但不应看到业务明文。Direct 只有在当前 generation 下完成加密确认后才能成为有效路径；旧候选、旧 peer session 和旧授权成员不能提升路径。

## 路径可观测性与隐私边界

客户端 daemon 到 Control 的活动路径遥测严格遵循最小泄露与代际围栏原则：
- 遥测仅传输抽象路径类型（direct、relay、connecting、probing、fallback_relay、failed、none）、往返 RTT、握手代际围栏标识与迁移原因代码。
- 绝不持久化或传输任何 IP 地址、端口、候选 endpoint、WireGuard 密钥、对称会话密钥或报文载荷。
- Control 校验上报端设备的会话凭据（WebSocket 认证或设备 token）、设备所属权与网络归属，并通过五级代际围栏（`registration_seq` > `network_generation` > `peer_session_generation` > `remote_candidate_epoch` > `observation_revision`）防御陈旧、越权或重放的路径上报。
- 只有持有 `CONTROL_ADMIN_TOKEN` 的管理员可通过只读 Admin Connections API 检索路径观测记录、受限历史迁移和小时级趋势聚合，普通节点不能任意拉取其他节点的路径观测。趋势表只保存 network ID、小时 bucket、计数与 RTT histogram，不长期保存 peer/device ID、IP、endpoint、密钥或业务载荷。

## 运维边界

Control 明文监听、Relay metrics、数据库、配置和密钥文件默认只在受保护的本机或容器网络中可见。公网只发布可信 HTTPS Control 和 Relay TLS。管理控制台如果启用，也只通过可信 HTTPS Control origin 访问；其令牌不写入公开日志、URL 或文档。日志、支持包和备份按敏感数据处理，不能把私钥、token、ticket 或业务明文写入公开产物。

项目处于 Preview，尚未完成独立安全审计。测试覆盖、CI 门禁和发布 manifest 不能替代外部审计或部署者自己的风险评估。
