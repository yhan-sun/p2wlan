# 自托管指南

## 部署单元

正式部署使用带有版本、提交和摘要的服务端归档。归档包含：

- p2wlan-control
- p2wlan-relay
- p2wlan-config
- p2wlan-db
- p2wlan-server、install-server.sh、deploy-server.sh
- BUILD-METADATA.txt 和 SHA256SUMS

普通部署不需要在服务器上安装 Go 或从源码构建。

## 已验证平台

仓库 CI 对服务端做分层验证：

| 范围 | 当前验证 |
| --- | --- |
| 原生服务端构建、Go 测试、Control/Relay 双进程 smoke | Ubuntu 22.04、Windows latest |
| systemd manager、backup/restore/rollback 契约 | Ubuntu 22.04 |
| Docker Compose 自托管拓扑 | Ubuntu 22.04 runner 上的 Docker |
| Linux 服务端静态二进制 loader 兼容 | Ubuntu 20.04 容器 |

这表示 Ubuntu 20.04 会验证发布形态的静态 Control/Relay 二进制可以启动并报告版本，但当前 CI 不声明 Ubuntu 20.04 的完整 systemd 管理、真实网络、TLS、升级恢复和长期运行已经端到端验收。正式部署优先使用已验证的 Ubuntu 22.04 或固定镜像；其他发行版在生产使用前自行执行安装、服务管理、TLS、数据库和业务连通性验证。

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
| HTTPS 443 | Control API、WebSocket | 是 |
| TLS 18081 | Relay 数据连接 | 是 |
| HTTP 18080 | Control 内部监听 | 否 |
| HTTP 18082 | Relay metrics、readyz | 否 |

Control 与 Relay 分机时，撤权 feed 使用 HTTPS 和独立 Bearer token。JWT、设备凭据、Relay ticket、票据签名密钥和 TLS 私钥不是同一种凭据。

## 配置

先用 p2wlan-config 在新目录生成匹配的 Control/Relay 配置，再按[配置参考](../reference/configuration.md)填入域名、证书和密钥。配置文件和数据库应由专用 p2wlan 用户拥有，权限分别限制为服务需要的最小范围。

Docker Compose 适合隔离验证或已建立镜像发布流程的部署。默认 Control 只发布到 loopback；容器以非 root、只读根文件系统和无额外 capability 运行。生产镜像必须来自固定发布摘要，不能在业务服务器上临时 build 未验证源码。

Compose 镜像也包含 `p2wlan-db`，可在挂载的数据卷上生成一致性 SQLite 快照；`p2wlan-server backup/restore` 只适用于服务端归档的 systemd 管理路径。容器恢复前先停止 Control，再用同一镜像的 `p2wlan-db --verify` 验证快照，最后启动并检查服务。

## 验证

    sudo p2wlan-server verify --service all
    sudo p2wlan-server check --service all

这些命令分别检查归档内容、版本和 Control/Relay 健康状态。它们不代替真实客户端、TUN、NAT、公网 TLS 或业务连通性验证。
