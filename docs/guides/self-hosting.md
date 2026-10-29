# 自托管指南

## 部署单元

正式部署使用带有版本、提交和摘要的服务端归档。归档包含：

- p2wlan-control
- p2wlan-relay
- p2wlan-config
- p2wlan-db
- p2wlan-server、install-server.sh、deploy-server.sh
- BUILD-METADATA.txt 和 SHA256SUMS

普通部署不需要在服务器上安装 Go、Node.js 或从源码构建。Linux systemd manager 的安装、升级和 doctor 需要 Python 3 标准库，以固定文件句柄检查和准备私有日志存储；该检查代码随同一归档的 manager 发布，不在线下载。管理台使用 React/TypeScript/Vite 开发，但 Vite 只在开发和 CI 构建阶段运行；生成的静态产物由 `go:embed` 编译进 `p2wlan-control`，发布后仍然是单一 Control 进程。

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

下载同一 server-vX.Y.Z 下与主机架构匹配的归档和同名 checksum，在专用目录中校验并解包。以下使用 amd64：

    sha256sum -c p2wlan-server-linux-amd64.tar.gz.sha256
    tar -xzf p2wlan-server-linux-amd64.tar.gz

全新同机部署先用同归档中的生成器创建匹配的 Control/Relay 配置。`/etc/p2wlan` 必须尚不存在；已有安装按下面的恢复步骤处理。将示例 endpoint 和证书路径替换为实际值，证书须覆盖 Relay 域名并受客户端信任：

```sh
sudo ./p2wlan-config --mode native --output /etc/p2wlan \
  --relay-endpoint tls://relay.example.com:18081 \
  --tls-cert /absolute/path/fullchain.pem \
  --tls-key /absolute/path/privkey.pem
sudoedit /etc/p2wlan/control.env
```

生成器的 native 模式默认把数据放在输出目录的 `data/` 下。使用标准 systemd 安装路径时，在首次启动前将 `control.env` 中以下两项改为：

```text
DB_PATH=/var/lib/p2wlan/p2pnet.db
LOG_UPLOAD_DIR=/var/lib/p2wlan/log-uploads
```

然后安装并验证发布包，完成 Control 的可信 HTTPS/WSS 入口后启动服务：

    sudo ./install-server.sh --archive p2wlan-server-linux-amd64.tar.gz --role all
    sudo p2wlan-server verify --service all
    sudo p2wlan-server start --service all
    sudo p2wlan-server check --service all

完成上述配置准备后，也可用 `sudo ./install-server.sh --version server-vX.Y.Z --role all` 下载并安装；版本必须与用于生成配置的已校验归档一致，安装后仍需显式启动并检查服务。

安装器保留已有配置。首次安装留下的未运行服务不会因安装发布包而自动启动；更新只重启此前正在运行的服务。`init` 生成的最小模板不包含完整 Relay 认证和 TLS 配置，须先补齐再显式启动。远程部署的 `--start` 同样要求配置已经完成。

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

`p2wlan-config` 在新目录生成匹配的 Control/Relay 配置，并复制提供的 TLS 证书和私钥；它不会覆盖已有目录。`--dev-localhost` 只生成隔离测试使用的本地证书，不能用于公网部署。其他字段见[配置参考](../reference/configuration.md)。配置文件和数据库应由专用 p2wlan 用户拥有，权限分别限制为服务需要的最小范围。

`p2wlan-config` 会和 JWT、Relay 凭据一起生成独立的 256-bit `CONTROL_ADMIN_TOKEN` 并写入受保护的 `control.env`，因此使用 `p2wlan-config` 的部署不需要手工制造管理台凭据。生成器不会把这些秘密打印到 stdout，也不会覆盖已有部署。

使用发布归档的 `install-server.sh` 安装时，`p2wlan-server init` 会为新部署分别生成 `JWT_SECRET` 和独立的 256-bit `CONTROL_ADMIN_TOKEN`，因此固定归档的标准安装路径默认具备管理台凭据，同时仍只在 Control 的受保护配置文件中保存秘密。对于早期已经存在、但缺少管理台凭据的部署，可以显式运行 `sudo p2wlan-server setup --role all` 补齐这一项；该命令不会轮换已有 JWT、Relay、TLS 或其他凭据。

支持日志使用独立的私有持久目录。标准安装显式设置 `LOG_UPLOAD_DIR` 为数据目录下的 `log-uploads`，不依赖进程工作目录；受管理目录由 `p2wlan` 拥有并限制为 `0700`。自定义值由部署者创建并检查服务账户和 systemd 的访问权限；Compose 自定义路径还须位于可写的持久挂载内。不要把支持日志放进发布目录或公共下载目录。

管理台入口为与 Control 同一可信 HTTPS origin 下的 `/admin/`；删除 `CONTROL_ADMIN_TOKEN` 并重启 Control 即可完全关闭管理面，此时 `/admin` 与 `/admin/*` 对任意 HTTP 方法都返回 404。当前管理台只读，不提供删除设备、修改房间或重启服务等写操作。

管理台源码位于 `server/admin-ui/`，`src/features/` 按功能组织页面，`src/layout/` 管理外壳，`src/components/ui/` 与 `src/shared/` 复用界面和交互，`src/styles/app.css` 是应用样式入口；CI 按锁文件执行 `npm ci` 并重新构建，再与仓库中已提交的 `server/admin/web/` 逐字节比对，因此源码改动后忘记重新构建会被 CI 拦下。服务端 tag / staging 构建也会在 `go build` 前重新执行 typecheck 和 production build，再由 Go 将生成目录嵌入 Control。这保证发布归档和本地 `go build` 都不会携带过期 UI，同时服务端安装和升级路径仍然只围绕原有服务端归档，不引入第二套前端发布流程。

管理员令牌不能与 `JWT_SECRET`、设备凭据、Relay ticket 或撤权 feed token 复用，也不要放入 URL、公开日志或反向代理访问日志字段。资源关系页面中的账号、membership、设备挂载、在线状态和 signaling 来自 Control 资源状态，不会据此推断数据面路径；连接排障页面（Connections）只读取 daemon 经 `path_telemetry_v1` 权威上报的路径快照与迁移历史；连接健康页面再基于这些已持久化事实和受限历史显示请求时 attention signals，不增加独立路径或告警状态。即使 observation 仍 fresh，也不等于目标 TUN 上的具体业务应用一定端到端可达。

Docker Compose 适合隔离验证或已建立镜像发布流程的部署。默认 Control 只发布到 loopback；容器以非 root、只读根文件系统和无额外 capability 运行。生产镜像必须来自固定发布摘要，不能在业务服务器上临时 build 未验证源码。

Compose 镜像也包含 `p2wlan-db`，可在挂载的数据卷上生成一致性 SQLite 快照；`p2wlan-server backup/restore` 只适用于服务端归档的 systemd 管理路径。容器恢复前先停止 Control，再用同一镜像的 `p2wlan-db --verify` 验证快照，最后启动并检查服务。

### Relay 配置缺失时恢复

`require-auth is enabled but no ticket keyring configured` 表示 Relay 没有可用的 `RELAY_TICKET_KEYRING_JSON`。保持 `RELAY_REQUIRE_AUTH=true`；补齐 keyring 后还需有匹配的 audience、region、撤权 feed 和 TLS。`setup` 只补齐缺失的管理台凭据，不会自动生成这些 Relay 配置。

如果安装仅有 `init` 模板，尚无 Relay 签名密钥、keyring 和 TLS，先备份现有配置，再从已校验的发布包向新的私有目录生成一对配置：

```sh
sudo /opt/p2wlan-server/current/p2wlan-config --mode native \
  --output /etc/p2wlan-relay-setup \
  --relay-endpoint tls://relay.example.com:18081 \
  --tls-cert /absolute/path/fullchain.pem \
  --tls-key /absolute/path/privkey.pem
sudo install -o p2wlan -g p2wlan -m 0600 /etc/p2wlan-relay-setup/tls.crt /etc/p2wlan/tls.crt
sudo install -o p2wlan -g p2wlan -m 0600 /etc/p2wlan-relay-setup/tls.key /etc/p2wlan/tls.key
sudoedit /etc/p2wlan-relay-setup/control.env /etc/p2wlan-relay-setup/relay.env \
  /etc/p2wlan/control.env /etc/p2wlan/relay.env
```

通过受保护的编辑器，从新 `control.env` 仅合入 `RELAY_CATALOG_JSON`、`RELAY_TICKET_SIGNER_JSON`、`RELAY_TICKET_TTL` 和 `RELAY_REVOCATION_FEED_TOKEN`；保留原 `JWT_SECRET`、`CONTROL_ADMIN_TOKEN`、`DB_PATH`、`LOG_UPLOAD_DIR` 与其他设置。从同一次生成的 `relay.env` 合入 Relay 设置，将其中 TLS 路径改为 `/etc/p2wlan/tls.crt` 和 `/etc/p2wlan/tls.key`。两份环境文件保持 `0600` 并归 `p2wlan` 所有。不要用新生成的整份 `control.env` 覆盖已有配置，也不要通过 shell `source` 加载包含 JSON 的环境文件。

如果 Control 已有签名密钥，应恢复对应的公钥 keyring，不重新生成签名密钥。使用包含 `--print-relay-keyring` 的同版本生成器，可从现有 PKCS#8 PEM 配置导出公钥；替换下面的文件名与 key id 为现有值：

```sh
sudo env RELAY_TICKET_SIGNER_KEY_FILE=/etc/p2wlan/relay-signing.pem \
  RELAY_TICKET_SIGNER_KID=existing-key-id \
  /opt/p2wlan-server/current/p2wlan-config --print-relay-keyring
```

输出仅为公钥 JSON，将完整结果写入 Relay 的 `RELAY_TICKET_KEYRING_JSON`。轮换期间还须提供现有的 `RELAY_TICKET_SIGNER_PREV_KEY_FILE` 与 `RELAY_TICKET_SIGNER_PREV_KID`。使用 `RELAY_TICKET_SIGNER_JSON` 的生成器部署，应优先恢复同次生成的 `relay.env`；不要把私钥 JSON 粘贴到命令参数或公开日志中。旧发布包缺少导出选项时，先按固定版本升级工具。

配置完成后重新加载两端，并验证 Relay 就绪：

    sudo p2wlan-server restart --service all
    sudo p2wlan-server check --service all
    sudo p2wlan-server doctor --service all

### Control 与 Relay 分机

从同一对配置分发：Control 保存 Ed25519 签名私钥，Relay 只需要其 key id 对应的 32 字节公钥。两台机器共享的是独立的 `RELAY_REVOCATION_FEED_TOKEN`，不分发 Control 的 JWT、管理台令牌或签名私钥到 Relay。

将 Relay 的 `RELAY_REVOCATION_FEED_URL` 改为 Control 的可信 HTTPS 地址加 `/api/v1/relay/revocations`，并保证 Relay 可访问它；生成器的 loopback feed 地址只适合同机。Control catalog 中的 `region`、`audience` 必须与该 Relay 一致，`endpoint` 必须是客户端可访问且与 TLS 证书匹配的地址。票据中的设备与网络范围由 Control 签发，不能通过填写 keyring 扩大。已配置的撤权 feed 尚未同步或已过期时，Relay 不会通过 readiness 检查或接受新的票据认证。

## 验证

    sudo p2wlan-server verify --service all
    sudo p2wlan-server check --service all
    sudo p2wlan-server doctor --service all

`verify` 检查发布归档和版本，`check` 检查本机 Control/Relay 健康端点，`doctor` 在此基础上继续检查 systemd、Admin 凭据、支持日志配置及服务账户的主机目录访问权限、SQLite 完整性、Relay TLS 文件、备份和数据盘空间。主机权限检查不进入运行服务的 mount namespace，也不写入支持包；完整上传仍需用户授权后实际验证。它们都不代替真实客户端、TUN、NAT、公网 TLS 入口或业务连通性验证。
