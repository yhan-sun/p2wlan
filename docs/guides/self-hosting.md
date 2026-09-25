# 自托管指南

## 部署单元

正式部署使用带有版本、提交和摘要的服务端归档。归档包含：

- p2wlan-control
- p2wlan-relay
- p2wlan-config
- p2wlan-db
- p2wlan-server、install-server.sh、deploy-server.sh
- BUILD-METADATA.txt 和 SHA256SUMS

普通部署不需要在服务器上安装 Go、Node.js 或从源码构建。管理台使用 React/TypeScript/Vite 开发，但 Vite 只在开发和 CI 构建阶段运行；生成的静态产物由 `go:embed` 编译进 `p2wlan-control`，发布后仍然是单一 Control 进程。

## 支持与验证范围

固定 `server-vX.Y.Z` 归档的公开部署契约是 Linux + systemd。仓库 CI 对服务端做分层验证：

| 运行形态 | 自动验证范围 | 边界 |
| --- | --- | --- |
| Linux 原生服务 | Ubuntu 22.04 上执行 Go vet、race/full tests、Control/Relay 双进程认证 smoke、IPv6 TLS/撤权验证和 manager contract | 这是固定服务端归档与 systemd manager 的主要验证路径 |
| 管理台前端 | 固定 Node 版本安装依赖，执行 TypeScript typecheck、Vite production build，并校验构建后的静态产物；服务端发布任务会在 Go 编译前再次构建管理台 | Node 只属于构建链，不进入生产服务器运行时 |
| Linux 静态服务端二进制 | Ubuntu 20.04 容器验证 `CGO_ENABLED=0` 产物没有动态 loader，并能执行 `--version` | 只证明基础 loader 兼容，不等于 Ubuntu 20.04 上完整 systemd、网络和业务链路已验收 |
| Docker Compose | Ubuntu 22.04 runner 构建实际 Debian bookworm 镜像、启动 Control/Relay、检查 readyz，并验证 SQLite 数据卷重启持久性 | 生产部署仍应使用固定镜像摘要并自行完成公网、TLS 和恢复演练 |
| Windows 服务端代码 | `windows-latest` 执行 Go vet/tests 和真实 Control/Relay 双进程 smoke | 当前固定 `server-vX.Y.Z` 发布归档不是 Windows 安装包，因此 Windows 不属于公开的固定归档部署路径 |

这表示 Ubuntu 20.04 会验证发布形态的静态 Control/Relay 二进制可以启动并报告版本，但当前 CI 不声明 Ubuntu 20.04 的完整 systemd 管理、真实网络、TLS、升级恢复和长期运行已经端到端验收。未列入完整验证矩阵的 Linux 发行版不能仅凭“能启动二进制”视为正式兼容；正式部署优先使用已验证的 Ubuntu 22.04 或固定镜像，并自行核对 systemd、文件权限、反向代理、TLS、数据库和内核网络能力。

## 安装

下载同一 server-vX.Y.Z 下与主机架构匹配的归档和同名 checksum：

    sha256sum -c p2wlan-server-linux-amd64.tar.gz.sha256
    sudo ./install-server.sh --archive p2wlan-server-linux-amd64.tar.gz --role all
    sudo p2wlan-server verify --service all

也可以让新机器的安装脚本按明确版本下载并校验归档：

    sudo ./install-server.sh --version server-vX.Y.Z --role all

安装器不会再从 main 或其他可变分支补取 manager；缺少同归档中的 manager 会直接失败。

## 网络边界

Control 的 HTTP 监听默认只在 loopback，公网通过可信 HTTPS 反向代理暴露，并保留 WebSocket Upgrade。Relay 使用独立的 TLS 入口；Relay 的 loopback metrics 和 readyz 不对公网开放。

推荐的最小公网入口：

| 入口 | 用途 | 公开 |
| --- | --- | --- |
| HTTPS 443 | Control API、WebSocket、可选 `/admin/` | 是 |
| TLS 18081 | Relay 数据连接 | 是 |
| HTTP 18080 | Control 内部监听 | 否 |
| HTTP 18082 | Relay metrics、readyz | 否 |

Control 与 Relay 分机时，撤权 feed 使用 HTTPS 和独立 Bearer token。JWT、设备凭据、Relay ticket、票据签名密钥和 TLS 私钥不是同一种凭据。

## 配置

先用 p2wlan-config 在新目录生成匹配的 Control/Relay 配置，再按[配置参考](../reference/configuration.md)填入域名、证书和密钥。配置文件和数据库应由专用 p2wlan 用户拥有，权限分别限制为服务需要的最小范围。

`p2wlan-config` 会和 JWT、Relay 凭据一起生成独立的 256-bit `CONTROL_ADMIN_TOKEN` 并写入受保护的 `control.env`，因此使用 `p2wlan-config` 的部署不需要手工制造管理台凭据。生成器不会把这些秘密打印到 stdout，也不会覆盖已有部署。

使用发布归档的 `install-server.sh` 安装时，`p2wlan-server init` 会为新部署分别生成 `JWT_SECRET` 和独立的 256-bit `CONTROL_ADMIN_TOKEN`，因此固定归档的标准安装路径默认具备管理台凭据，同时仍只在 Control 的受保护配置文件中保存秘密。对于早期已经存在、但缺少管理台凭据的部署，可以显式运行 `sudo p2wlan-server setup --role all` 补齐这一项；该命令不会轮换已有 JWT、Relay、TLS 或其他凭据。

管理台入口为与 Control 同一可信 HTTPS origin 下的 `/admin/`；删除 `CONTROL_ADMIN_TOKEN` 并重启 Control 即可完全关闭管理面，此时 `/admin` 与 `/admin/*` 对任意 HTTP 方法都返回 404。当前管理台只读，不提供删除设备、修改房间或重启服务等写操作。

管理台源码位于 `server/admin-ui/`；CI 按锁文件执行 `npm ci` 并重新构建，再与仓库中已提交的 `server/admin/web/` 逐字节比对，因此源码改动后忘记重新构建会被 CI 拦下。服务端 tag / staging 构建也会在 `go build` 前重新执行 typecheck 和 production build，再由 Go 将生成目录嵌入 Control。这保证发布归档和本地 `go build` 都不会携带过期 UI，同时服务端安装和升级路径仍然只围绕原有服务端归档，不引入第二套前端发布流程。

管理员令牌不能与 `JWT_SECRET`、设备凭据、Relay ticket 或撤权 feed token 复用，也不要放入 URL、公开日志或反向代理访问日志字段。资源关系页面中的账号、membership、设备挂载、在线状态和 signaling 来自 Control 资源状态，不会据此推断数据面路径；连接路径页面（Connections）只读取 daemon 经 `path_telemetry_v1` 权威上报的路径快照与迁移历史；连接健康页面再基于这些已持久化事实和受限历史显示请求时 attention signals，不增加独立路径或告警状态。即使 observation 仍 fresh，也不等于目标 TUN 上的具体业务应用一定端到端可达。

Docker Compose 适合隔离验证或已建立镜像发布流程的部署。默认 Control 只发布到 loopback；容器以非 root、只读根文件系统和无额外 capability 运行。生产镜像必须来自固定发布摘要，不能在业务服务器上临时 build 未验证源码。

Compose 镜像也包含 `p2wlan-db`，可在挂载的数据卷上生成一致性 SQLite 快照；`p2wlan-server backup/restore` 只适用于服务端归档的 systemd 管理路径。容器恢复前先停止 Control，再用同一镜像的 `p2wlan-db --verify` 验证快照，最后启动并检查服务。

## 验证

    sudo p2wlan-server verify --service all
    sudo p2wlan-server check --service all
    sudo p2wlan-server doctor --service all

`verify` 检查发布归档和版本，`check` 检查本机 Control/Relay 健康端点，`doctor` 在此基础上继续检查 systemd、Admin 凭据、SQLite 完整性、Relay TLS 文件、备份和数据盘空间。它们都不代替真实客户端、TUN、NAT、公网 TLS 入口或业务连通性验证。
