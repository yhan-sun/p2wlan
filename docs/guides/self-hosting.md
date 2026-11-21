# 自托管指南

通过自托管 P2WLAN 服务端，你可以拥有专属的控制面（Control）与加密中继（Relay），实现自主可控的私有组网基础设施。

---

## 部署方案概览

P2WLAN 服务端提供两种主流部署途径：

| 部署方式 | 适用场景 | 依赖要求 | 特点 |
| --- | --- | --- | --- |
| **Docker Compose（推荐）** | 生产环境、云服务器、易于维护 | Docker Engine、Docker Compose v2 | 容器化隔离、开箱即用、升级迁移方便 |
| **原生 Linux + systemd** | 追求轻量极致性能、无 Docker 环境 | Ubuntu / Debian 等主流 Linux，Python 3 | 零容器开销、systemd 统一管理生命周期 |

服务端已将 Web 管理控制台（Admin UI）打包并编译进 `p2wlan-control` 二进制中。生产部署无需额外安装 Node.js、Go 或从源码编译。

---

## 1. 一键快速部署

登录你的 Linux 云服务器，复制并运行以下命令，即可启动交互式部署向导：

```bash
curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/bootstrap-server.sh | sudo bash
```

> **向导流程简述**：
> 1. **选择安装方式**：输入 `1` 选择直接安装（systemd），或输入 `2` 选择 Docker 部署（默认）；
> 2. **自动检测与安装依赖**：向导会自动检查所需工具并提示安装缺失组件；
> 3. **选择版本**：默认选择最新正式发布的 `server-vX.Y.Z` 版本；
> 4. **配置 Relay 域名与 TLS**：输入客户端访问 Relay 所需的主机名（如 `relay.example.com`）及对应的 TLS 证书路径（`fullchain.pem` 与 `privkey.pem`）；
> 5. **确认并启动**：生成配套凭据后自动启动并进行健康度检查。

---

## 2. 自动化 / 无人值守安装

如果你希望将部署集成进自动化运维脚本（CI/CD、Ansible 或 Cloud-Init），可通过参数静默运行：

### Docker 方式自动化部署
```bash
curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/bootstrap-server.sh | sudo bash -s -- \
  --method docker --version server-vX.Y.Z --non-interactive --install-deps \
  --dir /opt/p2wlan-docker \
  --relay-endpoint tls://relay.example.com:18081 \
  --tls-cert /etc/ssl/p2wlan/fullchain.pem \
  --tls-key /etc/ssl/p2wlan/privkey.pem
```

### 原生 systemd 方式自动化部署
```bash
curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/bootstrap-server.sh | sudo bash -s -- \
  --method native --version server-vX.Y.Z --non-interactive --install-deps --start \
  --root /opt/p2wlan-server --config-dir /etc/p2wlan --data-dir /var/lib/p2wlan \
  --relay-endpoint tls://relay.example.com:18081 \
  --tls-cert /etc/ssl/p2wlan/fullchain.pem \
  --tls-key /etc/ssl/p2wlan/privkey.pem
```

---

## 3. 手动部署指南

如果你习惯先下载离线发布包再进行部署，可直接使用 GitHub Releases 发布的归档资产。

### 使用 Docker 离线部署包
1. 下载 `p2wlan-server-docker.tar.gz` 及其校验文件并解压：
   ```bash
   sha256sum -c p2wlan-server-docker.tar.gz.sha256
   mkdir p2wlan-server-docker && tar -xzf p2wlan-server-docker.tar.gz -C p2wlan-server-docker
   cd p2wlan-server-docker
   ```
2. 运行包内安装脚本：
   ```bash
   sudo bash ./install-server-docker.sh
   ```
3. 服务将在部署目录（默认 `/opt/p2wlan-docker`）生成 `compose.yml`、`.env` 以及服务配置文件。后续可通过标准命令维护：
   ```bash
   cd /opt/p2wlan-docker
   sudo docker compose ps
   sudo docker compose logs -f
   ```

### 使用原生 Linux 部署包
1. 下载对应架构的发布归档（如 `p2wlan-server-linux-amd64.tar.gz`）：
   ```bash
   sha256sum -c p2wlan-server-linux-amd64.tar.gz.sha256
   tar -xzf p2wlan-server-linux-amd64.tar.gz
   ```
2. 执行安装：
   ```bash
   sudo bash ./install-server.sh --archive p2wlan-server-linux-amd64.tar.gz --interactive
   ```

---

## 4. 网络端口与安全边界

为确保安全与通信正常，推荐按以下规范配置服务器端口与反向代理：

| 端口 / 协议 | 服务用途 | 公网开放建议 | 说明 |
| --- | --- | --- | --- |
| **TCP 443 (HTTPS)** | Control API、WebSocket 信令、Web 管理台 | **必须公开** | 外部由 Nginx / Caddy / Traefik 提供反向代理与 TLS 证书，须启用 WebSocket Upgrade |
| **TCP 18081 (TLS)** | Relay 密文数据转发通道 | **必须公开** | 由 Relay 服务原生监听并提供 TLS 加密通信 |
| **TCP 18080 (HTTP)** | Control 本地内部监听 | **禁止公开** | 仅绑定在 `127.0.0.1`，仅供反向代理访问 |
| **TCP 18082 (HTTP)** | Relay 内部健康检查与指标 | **禁止公开** | 仅供本地探活使用（`/readyz`） |

> [!IMPORTANT]
> **关于 Nginx 反向代理配置**：
> 代理 Control 服务时，请确保开启 WebSocket 支持：
> ```nginx
> location / {
>     proxy_pass http://127.0.0.1:18080;
>     proxy_http_version 1.1;
>     proxy_set_header Upgrade $http_upgrade;
>     proxy_set_header Connection "upgrade";
>     proxy_set_header Host $host;
>     proxy_set_header X-Real-IP $remote_addr;
> }
> ```

---

## 5. Web 管理控制台与凭据配置

安装向导在初始化时会自动生成一套高强度的随机凭据，保存在服务配置目录中（如 `/etc/p2wlan/control.env` 或容器挂载的 `config/control.env`）：
- `JWT_SECRET`：客户端登录与会话签名密钥；
- `CONTROL_ADMIN_TOKEN`：Web 管理控制台的管理员 Token（32 位随机密钥）。

如果希望启用 Web 管理控制台，请通过配置好的 HTTPS 地址访问 `https://your-domain/admin/`，输入该 Token 即可进入控制台。如需临时关闭管理台，只需在配置文件中清空 `CONTROL_ADMIN_TOKEN` 并重启 Control 服务即可。

---

## 6. 验证部署结果

部署完成后，可以通过以下命令检查各组件的存活与运行状态：

### Docker 环境验证
```bash
sudo docker compose ps
# 检查 Control 健康状态
sudo docker compose exec -T control sh -c 'curl -fsS http://127.0.0.1:$PORT/health'
# 检查 Relay 准备状态
sudo docker compose exec -T relay sh -c 'curl -fsS http://$RELAY_METRICS_BIND/readyz'
```

### 原生环境验证
```bash
# 服务版本校验
sudo p2wlan-server verify --service all
# 基础存活检查
sudo p2wlan-server check --service all
# 深度配置与系统诊断
sudo p2wlan-server doctor --service all
```

全部检查通过后，即可打开客户端填入该 Control 地址，尽情享受流畅的私网互联！
