# 安全模型

## 身份与凭据

设备控制面身份、数据面会话密钥、Relay ticket、JWT、管理控制台令牌、Relay 票据签名 key、撤权 feed token 和 TLS 私钥承担不同职责，不能互相替代。管理控制台令牌只授权同一 Control 实例的只读管理 API，不授予设备身份、房间成员身份或 Relay 数据连接权限。ticket 必须绑定 audience、region、设备/网络身份和短期过期时间；Relay 在撤权 feed 未就绪或过期时拒绝新的认证连接。

## 数据面

业务数据在端点之间使用加密会话。Relay 看到节点标识、时间、连接频率和包大小等元数据，但不应看到业务明文。Direct 只有在当前 generation 下完成加密确认后才能成为有效路径；旧候选、旧 peer session 和旧授权成员不能提升路径。

## 运维边界

Control 明文监听、Relay metrics、数据库、配置和密钥文件默认只在受保护的本机或容器网络中可见。公网只发布可信 HTTPS Control 和 Relay TLS。管理控制台如果启用，也只通过可信 HTTPS Control origin 访问；其令牌不写入公开日志、URL 或文档。日志、支持包和备份按敏感数据处理，不能把私钥、token、ticket 或业务明文写入公开产物。

项目处于 Preview，尚未完成独立安全审计。测试覆盖、CI 门禁和发布 manifest 不能替代外部审计或部署者自己的风险评估。
