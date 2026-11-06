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

Docker 部署使用独立的 `p2wlan-server-docker.tar.gz` 和同名 `.sha256`。包内含安装向导、生产 Compose 模板、`SERVER-IMAGE.json` 和该元数据的 checksum。元数据绑定服务端 tag、源码 SHA、多架构镜像摘要及平台；安装时拉取 `ghcr.io/yhan-sun/p2wlan/server@sha256:...`，不在业务服务器构建镜像，也不使用 `latest`。

## 支持与验证范围

固定 `server-vX.Y.Z` 原生归档的公开部署契约是 Linux + systemd；Docker 部署使用 Linux Docker Engine 和 Compose v2。仓库 CI 对服务端做分层验证：

| 运行形态 | 自动验证范围 | 边界 |
| --- | --- | --- |
| Linux 原生服务 | Ubuntu 22.04 上执行 Go vet、race/full tests、Control/Relay 双进程认证 smoke、IPv6 TLS/撤权验证和 manager contract | 这是固定服务端归档与 systemd manager 的主要验证路径 |
| 管理台前端 | 固定 Node 版本安装依赖，执行 TypeScript typecheck、Vite production build，并校验构建后的静态产物；服务端发布任务会在 Go 编译前再次构建管理台 | Node 只属于构建链，不进入生产服务器运行时 |
| Linux 静态服务端二进制 | Ubuntu 20.04 容器验证 `CGO_ENABLED=0` 产物没有动态 loader，并能执行 `--version` | 只证明基础 loader 兼容，不等于 Ubuntu 20.04 上完整 systemd、网络和业务链路已验收 |
| Docker Compose | Ubuntu 22.04 runner 构建实际 Debian bookworm 镜像、启动 Control/Relay、检查 readyz，并验证 SQLite 数据卷重启持久性 | 生产部署仍应使用固定镜像摘要并自行完成公网、TLS 和恢复演练 |
| Windows 服务端代码 | `windows-latest` 执行 Go vet/tests 和真实 Control/Relay 双进程 smoke | 当前固定 `server-vX.Y.Z` 发布归档不是 Windows 安装包，因此 Windows 不属于公开的固定归档部署路径 |

这表示 Ubuntu 20.04 会验证发布形态的静态 Control/Relay 二进制可以启动并报告版本，但当前 CI 不声明 Ubuntu 20.04 的完整 systemd 管理、真实网络、TLS、升级恢复和长期运行已经端到端验收。未列入完整验证矩阵的 Linux 发行版不能仅凭“能启动二进制”视为正式兼容；正式部署优先使用已验证的 Ubuntu 22.04 或固定镜像，并自行核对 systemd、文件权限、反向代理、TLS、数据库和内核网络能力。

## 安装

### 一条命令部署

登录 Linux 服务器，复制下面一整行运行，无需 clone 仓库、手动下载部署包或安装 Go / Node.js：

    curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/bootstrap-server.sh | sudo bash

这一下载入口需要系统已有 `curl` 和 `sudo`；root 终端可去掉 `sudo`。首屏先选择 `1` 直接安装（原生 systemd）、`2` Docker 部署（默认）或 `0` 退出，然后检查并询问是否安装该方式的缺失依赖。直接安装准备原生运行工具；Docker 方式准备 Docker Engine / Compose。自动准备环境支持 Ubuntu 22.04 / 24.04 / 26.04、Debian 12 / 13 的 amd64 / arm64 systemd 主机，Docker 使用官方 apt 源；其他 Linux 主机可在自行准备好对应运行环境后使用。

脚本只发现非 draft、非 prerelease、包含所选方式资产的正式 `server-vX.Y.Z`。直接安装要求与主机架构匹配的原生归档及同名 checksum；Docker 要求部署包、镜像元数据及各自同名 checksum 均上传完成。确认版本后下载同一 tag 的包，校验摘要与发布身份，再运行包内向导。按提示填写路径、Relay 地址和可信 TLS 文件，完成配套配置、启动与健康检查。整个流程通过当前终端交互，支持从 `curl` 管道启动。

这个入口要求 `main` 已提供 `bootstrap-server.sh`，并已有包含对应安装器与资产的正式服务端 Release。原生列表与 Docker 列表分别筛选，只有原生归档的版本不会出现在 Docker 列表中；历史归档仍须具备相应安装器接口。查找不到匹配发布或校验失败时会停止，不回退到未校验源码部署。公网 Control 的可信 HTTPS/WSS 反向代理和 Relay 证书仍由部署者准备。

引导脚本的 `main` 地址用于获取当前安装入口；实际程序和 Docker 模板、镜像来自一个已经解析并固定的 Release。重复部署时显式指定方式和 tag，例如选择 Docker：

    curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/bootstrap-server.sh | sudo bash -s -- --method docker --version server-vX.Y.Z --interactive

直接安装将 `--method docker` 换为 `--method native`。

自动发现最多读取 5 页、每页 100 条 Release。GitHub API 限流或需要直接选择较早版本时，可使用上面的明确版本命令绕过发现过程。

无人值守必须显式指定 `--version`，建议同时用 `--method` 明确方式，未传时默认 Docker；允许安装缺失依赖时再加 `--install-deps`。Docker 示例：

    curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/bootstrap-server.sh | sudo bash -s -- \
      --method docker --version server-vX.Y.Z --non-interactive --install-deps \
      --dir /opt/p2wlan-docker --relay-endpoint tls://relay.example.com:18081 \
      --tls-cert /etc/ssl/p2wlan/fullchain.pem --tls-key /etc/ssl/p2wlan/privkey.pem

直接安装示例：

    curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/bootstrap-server.sh | sudo bash -s -- \
      --method native --version server-vX.Y.Z --non-interactive --install-deps --start \
      --root /opt/p2wlan-server --config-dir /etc/p2wlan --data-dir /var/lib/p2wlan \
      --relay-endpoint tls://relay.example.com:18081 \
      --tls-cert /etc/ssl/p2wlan/fullchain.pem --tls-key /etc/ssl/p2wlan/privkey.pem

两种方式共用 `--relay-endpoint`、`--tls-cert`、`--tls-key`、`--control-port`、`--metrics-port`、`--dev-localhost`、`--no-start`；`--repo` 选择发布仓库。目录和运行参数分别如下，传入另一方式的专用参数会被拒绝：

| 方式 | 专用参数 | 默认路径 |
| --- | --- | --- |
| 直接安装 `native` | `--root`、`--config-dir`、`--data-dir`、`--start` | 程序 `/opt/p2wlan-server`；配置 `/etc/p2wlan`；数据 `/var/lib/p2wlan` |
| Docker `docker` | `--dir`、`--publish-host`、`--wait-timeout` | 持久目录 `/opt/p2wlan-docker` |

引导入口的无人值守部署默认安装并启动；`--no-start` 只准备原生安装或 Docker 部署文件。`--dry-run` 查询发布、下载并校验所选方式的包，但不安装依赖、不执行包内安装器或启动服务；主机仍须已有 Python 3 和 curl。它不能替代服务与公网连通性验收。

### 完整交互流程

1. **选择安装方式。** 首屏 `1` 是直接安装到系统、`2` 是 Docker 部署（默认）、`0` 退出。选择发生在依赖安装之前。
2. **检查对应环境。** 识别系统与架构，检查该方式所需工具。缺少依赖时选 `1` 安装或 `0` 退出，默认 `1`；已有可用环境会直接复用。原生分支使用 systemd，Docker 分支检查 Engine / Compose。
3. **选择发布版本。** 按发布时间从新到旧列出最多 15 个符合该方式资产要求的正式服务端 Release，默认 `1` 为最新一项；按编号选择、输入 `m` 手填固定 tag，或输入 `0` 取消。客户端 `vX.Y.Z` 不会混入列表，无效输入会要求重选。显式 `--version` 不重复选版。随后下载并校验同 tag 的对应包。
4. **确认持久路径。** 原生分支分别确认程序、配置与数据目录；Docker 分支确认一个持久部署目录，默认值见上表。已有部署进入保留配置和凭据的升级流程。
5. **选择部署模式。** 新部署选择公网服务或本机测试。公网服务使用已有可信证书；本机测试生成短期 loopback 测试证书，不面向公网客户端。
6. **填写 Relay 和 TLS。** 公网模式依次填写 Relay 域名或 IP、端口、完整证书链 PEM 路径、匹配私钥 PEM 路径。证书须覆盖所填主机名且在有效期内；向导不会签发公信证书。
7. **确认内部端口。** Control 内部 HTTP 默认 `18080`、Relay 健康检查默认 `18082`，Relay 端口默认 `18081`。Docker 还确认 Relay 发布绑定 IP，公网默认 `0.0.0.0`。Control 始终只发布到 loopback，公网 HTTPS/WSS 由外部反向代理提供。
8. **选择执行方式并确认摘要。** 启动方式选 `1` 安装并启动、`2` 只准备，默认 `1`。摘要列出固定版本、目录、Relay、端口、TLS 文件和执行方式，Docker 还列出镜像身份，不显示秘密；最后选 `1` 确认、`2` 重填、`0` 取消。已有部署保留配置，重填只调整允许的执行选项。
9. **自动执行并交付入口。** 原生分支安装已校验的二进制和 systemd unit；Docker 分支拉取固定摘要镜像。新部署生成匹配的 Control/Relay 配置。立即启动会等待健康检查，失败时报告排查入口；只准备不会声称服务已经健康。完成后显示本机 Control、Relay、管理台、凭据文件位置和对应方式的管理命令。

已有部署不会重新询问并生成一套新 JWT、管理台或 Relay 凭据；向导展示已保存的配置，让部署者确认升级和启动方式。更换 TLS 或调整既有参数应按下文的配置与证书维护步骤显式进行。

下面是选择 Docker 的新公网部署输入示例，省略环境准备、下载过程、实际版本列表和摘要内容；域名与证书路径应替换为自己的值。带默认值的项目可直接按回车接受：

```text
阶段一：选择安装方式
  1) 直接安装（Linux + systemd，不需要 Docker）
  2) Docker 部署（Docker Compose）
  0) 取消并退出
安装方式 [2]: 2
请选择版本编号 [1]: 1
[1/7] 部署目录
部署目录 [/opt/p2wlan-docker]: /opt/p2wlan-docker
[2/7] 部署模式
部署模式 [1]: 1
[3/7] Relay 公告地址
Relay主机（主机名或IP）: relay.example.com
Relay端口 [18081]: 18081
[4/7] TLS 证书
证书链路径: /etc/ssl/p2wlan/fullchain.pem
私钥路径: /etc/ssl/p2wlan/privkey.pem
[5/7] 监听端口与 Relay 绑定
Control端口 [18080]: 18080
metrics端口 [18082]: 18082
Relay绑定IP [0.0.0.0]: 0.0.0.0
[6/7] 启动方式
启动方式 [1]: 1
[7/7] 部署摘要
  1) 确认部署  2) 重新填写配置  0) 取消
确认部署 [1]: 1
```

字段格式、端口冲突或文件路径有误时会要求重填；Docker 配置向导中的输入步骤可输入 `取消` 退出。证书链、私钥匹配、主机名与有效期仍须通过配置生成器的实际检查；完成本机健康检查后，还需验证外部 HTTPS/WSS、Relay TLS 和真实客户端业务连通。

### 直接使用 Docker 部署包

主机需要 Python 3、本机运行的 Docker Engine 和 Compose v2；当前安装器使用 rootful Linux Engine，不支持远程 Docker context、rootless 或用户命名空间映射，也不自动安装 Docker。先确认 Docker 已启动且 `docker compose version` 可用，再在服务器上的仓库目录运行：

    sudo bash scripts/install-server-docker.sh

向导接收固定的 `server-vX.Y.Z`，从同一 Release 下载并校验 `SERVER-IMAGE.json`，按其中的精确摘要拉取镜像。首次部署填写 Relay 的 `tls://host:port` 地址、覆盖该主机名的完整证书链和匹配私钥路径。配置生成器在所选镜像中运行，自动生成匹配的 Control/Relay 凭据；安装器保存持久配置和数据库，启动 Compose 服务并等待健康检查。Control 默认只发布到 loopback，公网 HTTPS/WSS 仍由外部可信反向代理提供。

从 Release 下载 Docker 部署包后，无需 checkout 源码；先校验、解包，再运行包内向导。相邻的元数据已绑定该次发布，无需手抄镜像摘要：

    sha256sum -c p2wlan-server-docker.tar.gz.sha256
    mkdir p2wlan-server-docker
    tar -xzf p2wlan-server-docker.tar.gz -C p2wlan-server-docker
    cd p2wlan-server-docker
    sudo bash ./install-server-docker.sh

无人值守部署可明确指定版本和 TLS 参数：

    sudo bash scripts/install-server-docker.sh --non-interactive \
      --version server-vX.Y.Z --dir /opt/p2wlan-server-docker \
      --relay-endpoint tls://relay.example.com:18081 \
      --tls-cert /etc/ssl/p2wlan/fullchain.pem \
      --tls-key /etc/ssl/p2wlan/privkey.pem

也可用 `--image` 传入明确的 `repository@sha256:...` 引用。`--dir` 选择持久部署目录；重复运行保留已有配置、凭据和数据库，升级前仍应备份。`--dev-localhost` 使用仅用于隔离测试的 loopback 证书，不适合公网客户端。镜像仓库需要允许部署主机读取；私有 GHCR 包须先配置 Docker 登录，公开部署应由维护者将发布包的容器镜像设为公开可读，权限规则见 [GitHub Container registry 文档](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)。

`--no-start` 只准备配置和 Compose 文件，不启动或重建容器；`--wait-timeout` 设置启动健康检查期限。`--dry-run` 只展示部署计划，不调用 Docker、下载元数据或修改文件，不作为镜像和 TLS 已验证的证据。

部署目录保存 `compose.yml`、唯一的 Compose 参数文件 `.env`，以及 `config/` 下的服务配置、TLS 文件和持久 `data/`。在该目录执行 `sudo docker compose ps`、`sudo docker compose logs -f` 或 `sudo docker compose down` 管理服务；默认安装会启动服务，再次运行会读取已有配置并等待服务健康。不要删除 `config/data/` 来更新镜像，也不要在日志或工单中公开 `.env` 和服务配置内容。

首次安装会将指定证书与私钥复制为 `config/tls.crt` 和 `config/tls.key`。续期只更新原输入路径不会生效；需要显式替换部署目录中的这两个文件，保持原 UID/GID 和 `0600` 权限，执行 `sudo docker compose restart relay`，再验证公网 TLS 证书链和 `/readyz`。

### 原生 systemd 交互安装

登录 Linux 服务器，在仓库目录运行：

    sudo bash scripts/install-server.sh

无参数时进入终端向导，也可显式使用 `--interactive`。首次同机部署 Control + Relay 时，按提示填写固定的 `server-vX.Y.Z`、客户端可访问的 `tls://host:port` Relay 地址、完整证书链和匹配私钥的本机路径。证书须覆盖 Relay 地址中的主机名且在有效期内；公网客户端还必须信任其签发链。

主机须已运行 systemd。缺少 Python 3、curl、OpenSSL 等工具时，向导可提示使用 `apt-get` 或 `dnf` 安装；无人值守安装可显式加 `--install-deps`。没有支持的包管理器时，先按脚本提示安装所缺工具。

向导先校验发布包与配置，再生成匹配的 JWT、管理台令牌、Relay 签票密钥和撤权凭据，安装 systemd 服务，最后启动并等待本机健康检查。秘密只写入受保护的配置文件，不打印到终端。重复运行保留已有配置和数据；已有配置需要修复时不会通过重新生成来轮换凭据。选择不启动或传入 `--no-start` 时，只安装，不启用或重启服务。

此安装流程要求同一归档内的 manager 支持 `update --no-restart`；首次生成配套配置还要求生成器支持 `--config-dir` 和 `--data-dir`。不具备相应接口的历史归档会在写入持久配置和安装服务前被拒绝，须选择包含这些接口的固定服务端发布包。

Control 保持 loopback HTTP 监听。公网部署还需准备可信 HTTPS/WSS 反向代理，并按下文的网络边界放行入口；向导不自动签发公信证书或修改防火墙。`--dev-localhost` 只用于隔离的本机测试，其证书不受正式客户端信任。

### 原生固定版本与无人值守安装

脚本可按明确版本下载同一 tag 的归档和 checksum。交互时只需预填版本：

    sudo bash scripts/install-server.sh --version server-vX.Y.Z --interactive

无人值守首次同机部署需要显式提供 TLS 配置；将示例版本、地址和路径替换为实际值：

    sudo bash scripts/install-server.sh --non-interactive \
      --version server-vX.Y.Z --role all \
      --relay-endpoint tls://relay.example.com:18081 \
      --tls-cert /etc/ssl/p2wlan/fullchain.pem \
      --tls-key /etc/ssl/p2wlan/privkey.pem --start

已有下载包可用 `--archive FILE` 代替 `--version`。归档旁必须保留同名 `.sha256` 文件；安装器从已校验的同一归档提取 manager 和配置生成器，不依赖脚本旁另有 manager，也不从 `main` 或其他可变分支补取文件。使用发布包内的脚本时，先校验并解包对应架构的完整归档：

    sha256sum -c p2wlan-server-linux-amd64.tar.gz.sha256
    tar -xzf p2wlan-server-linux-amd64.tar.gz
    sudo bash ./install-server.sh --archive p2wlan-server-linux-amd64.tar.gz --interactive

可使用 `--root DIR --config-dir DIR --data-dir DIR` 指定绝对安装、配置和数据目录，或加 `--dry-run` 仅校验归档摘要、内部文件和元数据并查看计划；dry-run 不执行包内程序或验证部署配置。未启用交互时，脚本不会读取终端输入，默认不启动服务；无人值守任务应传入 `--non-interactive` 和所需参数，需要启动时显式加 `--start`。

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

交互安装器复用发布包内的 `p2wlan-config` 生成匹配的 Control/Relay 配置，无需手工拼接密钥和 JSON。需要单独生成时，在新目录运行 `p2wlan-config`，参数和环境变量见[配置参考](../reference/configuration.md)。native 模式可用 `--config-dir` 和 `--data-dir` 指定配置中的最终运行路径，便于先在 staging 目录生成再安装；生成器仍只写入 `--output` 的新目录，不创建这些外部运行目录。配置文件和数据库由专用 p2wlan 用户拥有，权限限制为服务需要的最小范围。

`p2wlan-config` 会和 JWT、Relay 凭据一起生成独立的 256-bit `CONTROL_ADMIN_TOKEN` 并写入受保护的 `control.env`，因此使用 `p2wlan-config` 的部署不需要手工制造管理台凭据。生成器不会把这些秘密打印到 stdout，也不会覆盖已有部署。

使用发布归档的 `install-server.sh` 安装时，`p2wlan-server init` 会为新部署分别生成 `JWT_SECRET` 和独立的 256-bit `CONTROL_ADMIN_TOKEN`，因此固定归档的标准安装路径默认具备管理台凭据，同时仍只在 Control 的受保护配置文件中保存秘密。对于早期已经存在、但缺少管理台凭据的部署，可以显式运行 `sudo p2wlan-server setup --role all` 补齐这一项；该命令不会轮换已有 JWT、Relay、TLS 或其他凭据。

支持日志使用独立的私有持久目录。标准安装显式设置 `LOG_UPLOAD_DIR` 为数据目录下的 `log-uploads`，不依赖进程工作目录；受管理目录由 `p2wlan` 拥有并限制为 `0700`。自定义值由部署者创建并检查服务账户和 systemd 的访问权限；Compose 自定义路径还须位于可写的持久挂载内。不要把支持日志放进发布目录或公共下载目录。

管理台入口为与 Control 同一可信 HTTPS origin 下的 `/admin/`；删除 `CONTROL_ADMIN_TOKEN` 并重启 Control 即可完全关闭管理面，此时 `/admin` 与 `/admin/*` 对任意 HTTP 方法都返回 404。当前管理台只读，不提供删除设备、修改房间或重启服务等写操作。

管理台源码位于 `server/admin-ui/`，`src/features/` 按功能组织页面，`src/layout/` 管理外壳，`src/components/ui/` 与 `src/shared/` 复用界面和交互，`src/styles/app.css` 是应用样式入口；CI 按锁文件执行 `npm ci` 并重新构建，再与仓库中已提交的 `server/admin/web/` 逐字节比对，因此源码改动后忘记重新构建会被 CI 拦下。服务端 tag / staging 构建也会在 `go build` 前重新执行 typecheck 和 production build，再由 Go 将生成目录嵌入 Control。这保证发布归档和本地 `go build` 都不会携带过期 UI；管理台随 Control 二进制或同版本服务端镜像发布，不引入独立前端发布流程。

管理员令牌不能与 `JWT_SECRET`、设备凭据、Relay ticket 或撤权 feed token 复用，也不要放入 URL、公开日志或反向代理访问日志字段。资源关系页面中的账号、membership、设备挂载、在线状态和 signaling 来自 Control 资源状态，不会据此推断数据面路径；连接排障页面（Connections）只读取 daemon 经 `path_telemetry_v1` 权威上报的路径快照与迁移历史；连接健康页面再基于这些已持久化事实和受限历史显示请求时 attention signals，不增加独立路径或告警状态。即使 observation 仍 fresh，也不等于目标 TUN 上的具体业务应用一定端到端可达。

Docker 生产部署使用 `deploy/selfhost/compose.production.yml`，该模板只接收固定镜像，不包含 build。`deploy/selfhost/compose.yml` 保留给 CI 和源码验证。默认 Control 只发布到 loopback；容器以非 root、只读根文件系统和无额外 capability 运行。生产镜像来自固定发布摘要，不能在业务服务器上临时 build 未验证源码。

Compose 镜像也包含 `p2wlan-db`。在部署目录中，可用运行中的 Control 容器生成一致性 SQLite 快照，输出仍位于私有持久数据目录：

    sudo docker compose exec -T control sh -c 'umask 077; mkdir -p /data/backups; exec p2wlan-db --source /data/p2pnet.db --output "/data/backups/database-$(date -u +%Y%m%dT%H%M%SZ).sqlite"'

快照应另行复制到受保护的独立备份存储。恢复前先停止 Control 和 Relay，用同一固定镜像的 `p2wlan-db --verify` 验证快照，再按原 UID/GID 和私有权限恢复数据库；只有服务完全停止后才处理旧 WAL/SHM 文件。最后启动并检查健康、账号与业务数据。`p2wlan-server backup/restore` 只适用于原生归档的 systemd 管理路径，不管理 Docker 数据卷。

## 验证

Docker 部署在持久部署目录中检查容器与内部健康端点：

    sudo docker compose ps
    sudo docker compose exec -T control sh -c 'curl -fsS --connect-timeout 3 --max-time 10 "http://127.0.0.1:$PORT/health"'
    sudo docker compose exec -T relay sh -c 'curl -fsS --connect-timeout 3 --max-time 10 "http://$RELAY_METRICS_BIND/readyz"'

原生 systemd 部署使用 manager：

    sudo p2wlan-server verify --service all
    sudo p2wlan-server check --service all
    sudo p2wlan-server doctor --service all

`verify` 检查发布归档和版本，`check` 检查本机 Control/Relay 健康端点，`doctor` 在此基础上继续检查 systemd、Admin 凭据、支持日志配置及服务账户的主机目录访问权限、SQLite 完整性、Relay TLS 文件、备份和数据盘空间。主机权限检查不进入运行服务的 mount namespace，也不写入支持包；完整上传仍需用户授权后实际验证。它们都不代替真实客户端、TUN、NAT、公网 TLS 入口或业务连通性验证。
