# 发布契约

## 身份链

发布必须绑定一个准确的源码 SHA：

    源码 SHA → 同 SHA 必需门禁 → 候选产物 → 签名 → 产物身份检查 → 摘要清单 → Release

客户端版本 tag 必须指向已经进入 main 的提交。发布 workflow 会查询该 SHA 的已完成 Actions 记录；CI、客户端/安装包、Windows/Mobile 生命周期、自托管服务、安全、NAT、路径、MTU、房间和 Rekey 等必需检查缺失或失败时，不构建正式发布产物。旧 SHA 的绿色结果不能证明新 SHA 可发布。

daemon、服务端和客户端产物必须能报告或验证源码提交、组件版本、架构和文件摘要。

daemon 构建脚本使用只读 Git 查询，避免身份检查自身刷新已监听的索引。Cargo 监听 Git 解析出的 HEAD、索引、已存在的 packed refs 和当前分支；分支引用仅被打包时，监听其最近存在的父目录，以检测后续重新出现的 loose ref。链接 worktree 使用其独立 HEAD/索引和共享引用路径，未变化的输入允许复用编译。显式 `P2WLAN_SOURCE_IDENTITY_REFRESH` 及冻结身份字段继续按原契约刷新和校验；新出现的未跟踪文件仍需调用方使用既有源码快照刷新入口，不能把 Cargo 缓存命中当作完整源码快照证明。

客户端 `vX.Y.Z` 与服务端 `server-vX.Y.Z` 是独立版本命名空间。相同数字后缀不代表相同源码 SHA、构建时间或发布集合；部署记录必须保存各自准确的 tag 与 commit。

## 产物

客户端发布前，各平台构建任务先生成最终候选产物，并为主要候选产物写入只在 CI 内流转的 artifact metadata。metadata 绑定文件名、源码 SHA、tag、平台、架构、文件大小、最终 SHA-256 和身份验证方式。汇总任务必须重新计算最终文件摘要并校验 metadata；任何源码、平台、架构、大小或摘要不一致都会阻止发布。

完整性检查通过后才生成公开的 `RELEASE-MANIFEST.json`、创建 draft Release、上传完整公开资产并发布。CI metadata sidecar 不作为下载资产公开；其身份字段会进入公开 manifest。服务端使用独立的 `server-vX.Y.Z` 标签，不与客户端 latest 混用。服务端归档内必须包含匹配的 Control、Relay、配置生成器、数据库快照工具、manager、安装器和 BUILD-METADATA。

服务端 tag 构建还发布同一源码 SHA 的 `linux/amd64`、`linux/arm64` GHCR 镜像，并在两种平台上检查 Control/Relay 的嵌入版本与提交。`SERVER-IMAGE.json` 绑定服务端 tag、`source_sha`、多架构镜像摘要和平台，附同名 `.sha256`；独立的 `p2wlan-server-docker.tar.gz` 部署包包含该元数据、checksum、交互安装器和生产 Compose 模板。GitHub 服务端 Release 必须等待原生归档和镜像任务均成功，校验身份后一起发布；部署使用 `repository@sha256:...`，不依赖可变 tag 解析结果。

Android 生产签名只在受保护的 release-signing 环境和版本 tag 中执行。分支构建不能取得生产签名秘密。Android 原生桥使用当前 Flutter SDK 声明的固定 NDK 版本；找不到该版本时发布失败，不扫描并选择 runner 上任意最新 NDK。

客户端远程安装器必须显式接收 `vX.Y.Z`，并从同一个 tag 下载包和 checksum。服务端实际部署也必须绑定一个固定 `server-vX.Y.Z`、相邻发布元数据或明确的镜像摘要；`latest` 或可变 `main` 不是可复现的服务端程序或镜像输入。

`bootstrap-server.sh` 的公开 `main` URL 是可更新的方式选择、环境准备与发布发现入口。交互时先选择原生 systemd 或 Docker，再只准备对应依赖并发现正式 `server-vX.Y.Z`：原生方式要求当前主机架构的服务端归档和 checksum，Docker 方式要求完整部署包、镜像元数据及各自 checksum。一经选择，本次下载与验证全部使用该准确 tag 的包、checksum 和包内身份；Docker 还绑定固定镜像摘要，不从 `main` 补取 manager、Compose 或服务端程序。无人值守必须显式提供 `--version`，并应以 `--method native|docker` 明确部署方式。

Docker 部署目录 `.env` 保存解析后的版本、提交和镜像引用；原生安装的 `current/BUILD-METADATA.txt` 保存版本、源码提交与架构。重新执行引导入口本身不代表重新部署了同一版本，需要复现时必须使用对应的固定身份。

Linux CLI 远程安装器对 `--version TAG`、`--version=TAG` 和 `P2WLAN_VERSION` 使用同一校验：标签以 `v` 开头，后面至少一个字符，且完整标签只能包含 ASCII 字母、数字、点、下划线和连字符。路径分隔符、查询参数、片段和空白会在选择或下载包之前被拒绝，`--dry-run` 同样执行该校验。校验只约束标签格式，不证明标签存在或对应正式版本；正式安装仍应选择明确的 `vX.Y.Z` Release。随发布包提供的本地安装器不要求远程版本参数。

## 发布后审计

从 `v0.1.170` 开始，客户端 manifest 使用 schema 3，完整集合包含 OpenWrt 24.10 IPK 和 25.12 APK 的十个原生架构包，共二十个 payload 加 manifest。OpenWrt 候选产物绑定固件系列和准确包架构，并通过匹配内核的 QEMU 安装、TUN 和 procd 生命周期门禁。缺少任一原生包时发布失败。历史版本仍按 schema 2 的集合审计，新版本不能降级 schema 隐藏缺失资产。

客户端 Release 发布后，`Release Post-publish Audit` 会重新从 GitHub API 解析 tag、Release 和资产摘要，并下载已发布的 `RELEASE-MANIFEST.json`。审计要求：

- tag 最终解析到一个 main 可达的准确提交；
- manifest 的 `source_sha` 与 tag commit 完全一致；
- Release 资产集合与 manifest 契约一致，不缺失也不多出未声明文件；
- 每个已发布资产的 GitHub `digest` 和文件大小与 manifest 记录一致；
- 已发布 manifest 自身的 GitHub `digest` 与下载后的文件一致。

该审计验证的是已经公开的 Release 对象，而不是 Actions 临时候选文件。当前仓库未把 GitHub Release immutability 写成代码内可执行保证；启用仓库级 immutable releases 后，可以把 `--require-immutable` 作为额外强制条件。

## 证据

Release 中的 `RELEASE-MANIFEST.json` 记录源码 SHA、tag，以及公开文件的文件名、大小和 SHA-256；主要安装包还记录平台、架构和构建身份验证方式。发布后审计另外生成独立的 `audit-report.json` Actions artifact，记录解析出的 tag commit、资产数量、manifest 摘要和 immutable 状态。

这些证据证明最终下载文件、manifest 和 tag 的一致关系，不等于独立安全审计、真实设备验收或公网可用性证明。

真实设备和公网验收应在外部记录中绑定最终安装包摘要、两端版本、Control/Relay 版本、网络类型、时间线和业务结果；未完成的项目不能写入公共文档为已完成。
