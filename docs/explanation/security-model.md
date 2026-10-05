# 安全模型

## 身份与凭据

设备控制面身份、数据面会话密钥、Relay ticket、JWT、管理控制台令牌、Relay 票据签名 key、撤权 feed token 和 TLS 私钥承担不同职责，不能互相替代。管理控制台令牌只授权同一 Control 实例的只读管理 API，不授予设备身份、房间成员身份或 Relay 数据连接权限。ticket 必须绑定 audience、region、设备/网络身份和短期过期时间；Relay 在撤权 feed 未就绪或过期时拒绝新的认证连接。

## 本地诊断认证

桌面 daemon 的本地诊断密钥按进程生成，重启时更换，没有闲置到期机制。客户端每次请求读取当前发现文件；`/health` 可公开探活，`/status` 等私有接口仍要求 Bearer 认证。本地 401 不能解释为 Control 登录到期，也不能证明已有 Direct 或 Relay 数据面已停止。

诊断发现目录由独占文件锁保护，同一目录不能同时供多个 daemon 发布密钥。不同配置或端口的实例必须使用各自的运行目录。密钥文件被清理后，持有发现目录锁的进程可重新发布同一密钥；Unix 发布保持 `0600`，提权进程保留启动时确定的目录所有者，Windows 保留交互用户的受限 ACL。退出清理只删除仍匹配本进程密钥的文件，不删除锁文件或继任实例的凭据。

Unix 发现目录的发布、修复和清理绑定目录与锁文件句柄。重建最后一级目录时保留原属主及 `0700`，不递归重建缺失的祖先，也不接管其他用户或重定向后的目录。桌面启动的遗留权限恢复只接受 sudo/pkexec 声明的实际调用 UID，并以账户数据库中的主目录限定默认应用路径；固定文件逐个验证，活动锁冲突时拒绝恢复。提权 daemon 原子保存配置时继承已固定配置目录的属主，新文件及替换文件均为 `0600`。

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

项目尚未完成独立安全审计，不声明安全认证。测试覆盖、CI 门禁和发布 manifest 不能替代外部审计或部署者自己的风险评估。
