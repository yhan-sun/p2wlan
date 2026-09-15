# P2WLAN 文档

这里的文档面向使用者、部署者和贡献者，描述当前代码已经提供的行为。它不是开发日志、阶段报告或发布证据仓库。

## 从哪里开始

- [快速开始](quickstart.md)：安装客户端、配置 Control、登录、加入房间并验证业务连通。
- [客户端指南](guides/client.md)：CLI、daemon、诊断和支持包。
- [房间指南](guides/rooms.md)：房间成员、权限、地址和多房间使用。
- [自托管指南](guides/self-hosting.md)：固定版本服务端包、Control、Relay、TLS 和 Compose。
- [升级与恢复](guides/upgrade-and-recovery.md)：备份、恢复、回滚和失败边界。
- [运维指南](guides/operations.md)：服务管理、证书、日志、健康检查和数据保护。
- [排障指南](guides/troubleshooting.md)：按 Control、Relay、Direct、路由和业务数据面定位问题。

## 准确规则

- [配置参考](reference/configuration.md)
- [CLI 参考](reference/cli.md)
- [网络参考](reference/networking.md)
- [兼容性参考](reference/compatibility.md)
- [发布契约](reference/release-contract.md)
- [路径可观测性](reference/path-observability.md)

## 长期机制

- [架构](explanation/architecture.md)
- [工程质量与架构边界](explanation/engineering-quality.md)
- [安全模型](explanation/security-model.md)
- [连接生命周期](explanation/connection-lifecycle.md)

## 文档边界

- README 只保留产品定位、限制和最短入口；操作细节放在 guides，准确字段放在 reference，长期机制放在 explanation。
- 部署脚本、配置生成器、测试和 workflow 是可执行契约；文档不能取代它们。
- 源码审查、测试输出、真实设备验收、staging 记录和发布清单不复制到 docs/，而是绑定到对应 PR、Issue 或 Release 资产。
- 示例始终使用 example.com、占位符和演示数据。真实地址、密钥、token、用户目录和日志禁止进入仓库。
