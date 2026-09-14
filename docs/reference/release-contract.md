# 发布契约

## 身份链

发布必须绑定一个准确的源码 SHA：

    源码 SHA → 必需门禁 → 候选产物 → 签名 → 产物身份检查 → 摘要清单 → Release

daemon、服务端和客户端产物必须能报告或验证源码提交、组件版本、架构和文件摘要。旧 SHA 的绿色结果不能证明新 SHA 可发布。

## 产物

客户端发布前，所有平台产物先作为 Actions artifact 汇总；完整性检查通过后才创建并发布 Release。服务端使用独立的 server-vX.Y.Z 标签，不与客户端 latest 混用。服务端归档内必须包含匹配的 Control、Relay、配置生成器、数据库快照工具、manager、安装器和 BUILD-METADATA。

Android 生产签名只在受保护的 release-signing 环境和版本 tag 中执行。分支构建不能取得生产签名秘密。

客户端远程安装器必须显式接收 `vX.Y.Z`，并从同一个 tag 下载包和 checksum；服务端安装器同样必须显式接收 `server-vX.Y.Z`。`latest` 或可变 `main` 不是可复现部署输入。

## 证据

Release 中的 RELEASE-MANIFEST.json 记录源码 SHA、tag、文件名、大小和 SHA-256。它证明发布文件与构建对象的对应关系，不等于独立安全审计、真实设备验收或公网可用性证明。

真实设备和公网验收应在外部记录中绑定最终安装包摘要、两端版本、Control/Relay 版本、网络类型、时间线和业务结果；未完成的项目不能写入公共文档为已完成。
