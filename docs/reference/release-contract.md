# 发布契约

## 身份链

发布必须绑定一个准确的源码 SHA：

    源码 SHA → 同 SHA 必需门禁 → 候选产物 → 签名 → 产物身份检查 → 摘要清单 → Release

客户端版本 tag 必须指向已经进入 main 的提交。发布 workflow 会查询该 SHA 的已完成 Actions 记录；CI、客户端/安装包、Windows/Mobile 生命周期、自托管服务、安全、NAT、路径、MTU、房间和 Rekey 等必需检查缺失或失败时，不构建正式发布产物。旧 SHA 的绿色结果不能证明新 SHA 可发布。

daemon、服务端和客户端产物必须能报告或验证源码提交、组件版本、架构和文件摘要。

## 产物

客户端发布前，所有平台产物先作为 Actions artifact 汇总；完整性检查通过后才创建并发布 Release。服务端使用独立的 server-vX.Y.Z 标签，不与客户端 latest 混用。服务端归档内必须包含匹配的 Control、Relay、配置生成器、数据库快照工具、manager、安装器和 BUILD-METADATA。

Android 生产签名只在受保护的 release-signing 环境和版本 tag 中执行。分支构建不能取得生产签名秘密。Android 原生桥使用当前 Flutter SDK 声明的固定 NDK 版本；找不到该版本时发布失败，不扫描并选择 runner 上任意最新 NDK。

客户端远程安装器必须显式接收 `vX.Y.Z`，并从同一个 tag 下载包和 checksum；服务端安装器同样必须显式接收 `server-vX.Y.Z`。`latest` 或可变 `main` 不是可复现部署输入。

## 发布后审计

客户端 Release 发布后，`Release Post-publish Audit` 会重新从 GitHub API 解析 tag、Release 和资产摘要，并下载已发布的 `RELEASE-MANIFEST.json`。审计要求：

- tag 最终解析到一个 main 可达的准确提交；
- manifest 的 `source_sha` 与 tag commit 完全一致；
- Release 资产集合与 manifest 契约一致，不缺失也不多出未声明文件；
- 每个已发布资产的 GitHub `digest` 和文件大小与 manifest 记录一致；
- 已发布 manifest 自身的 GitHub `digest` 与下载后的文件一致。

该审计验证的是已经公开的 Release 对象，而不是 Actions 临时候选文件。当前仓库未把 GitHub Release immutability 写成代码内可执行保证；启用仓库级 immutable releases 后，可以把 `--require-immutable` 作为额外强制条件。

## 证据

Release 中的 RELEASE-MANIFEST.json 记录源码 SHA、tag、文件名、大小和 SHA-256。发布后审计另外生成独立的 `audit-report.json` Actions artifact，记录解析出的 tag commit、资产数量、manifest 摘要和 immutable 状态。

这些证据证明发布文件、manifest 和 tag 的一致关系，不等于独立安全审计、真实设备验收或公网可用性证明。

真实设备和公网验收应在外部记录中绑定最终安装包摘要、两端版本、Control/Relay 版本、网络类型、时间线和业务结果；未完成的项目不能写入公共文档为已完成。
