# P2WLAN 服务端部署

第一次自托管、Windows 原生运行或 Docker Compose，请先阅读 [从空目录启动 Control 与 Relay](self-hosting.md)。该指南包含组件关系、TLS/票据/撤权配置、配置生成器和完整验证；本页主要说明已有 Linux 安装的包管理与升级。

服务端分为 control 和 relay 两个进程。control 提供账号、设备注册、持久化信令和 Relay 票据；relay 只转发已认证的密文。客户端不会自动使用任何项目服务器，安装后必须手动填写自己的 control URL。

部署有两条等价路径。服务端 Release 构建成功、GitHub Release 发布成功和实际部署健康检查是三个独立结果；只有最后一项通过，才算服务器部署完成。

| 路径 | 适用场景 | 凭据 | 服务器如何取得包 |
| --- | --- | --- | --- |
| 本地上传 | 用户手动从 Actions/Release 下载后部署 | 本机 SSH key，或 SSH 交互密码；远端 sudo 交互密码 | `scripts/deploy-server.sh` 用 `scp` 上传并再次校验 SHA256 |
| 服务端拉取 | 已经安装过 manager，希望只输入版本 | SSH key，或 SSH 交互密码；远端 sudo 交互密码 | 服务器上的 `p2wlan-server update --version` 通过 HTTPS 拉取并校验 |
| Actions staging | 受控测试机自动验证 | GitHub Environment 中的 CI 专用 SSH key 和 known_hosts | workflow 上传构建包，或让 staging 主机自行拉取 |

密码不会写进命令行。手动部署时省略 `--identity`，OpenSSH 会在终端提示 SSH 密码；远端执行 `sudo` 时会在同一个终端提示管理员密码。Actions runner 没有可交互的密码输入，因此必须使用 staging Environment 的专用 SSH key，并配置非交互的最小 sudo 权限。不要把 `~/.ssh/ali.pem` 或任何密码提交到 Git、Actions artifact、Issue 或日志。

## 安装

从服务端 Release 下载对应架构的 `p2wlan-server-linux-amd64.tar.gz` 或 `p2wlan-server-linux-arm64.tar.gz`，同时下载同名 `.sha256` 文件。把两个文件和包内的 `install-server.sh`、`p2wlan-server` 放在同一目录后运行：

```bash
sha256sum -c p2wlan-server-linux-amd64.tar.gz.sha256
sudo ./install-server.sh --archive p2wlan-server-linux-amd64.tar.gz --role all
sudo p2wlan-server status
```

在线安装必须指定完整的 `server-vX.Y.Z` 版本：

```bash
curl -fLO https://github.com/yhan-sun/p2wlan/releases/download/server-vX.Y.Z/p2wlan-server-linux-amd64.tar.gz
curl -fLO https://github.com/yhan-sun/p2wlan/releases/download/server-vX.Y.Z/p2wlan-server-linux-amd64.tar.gz.sha256
sudo ./install-server.sh --version server-vX.Y.Z --role all
```

默认目录是：程序 `/opt/p2wlan-server`，配置 `/etc/p2wlan`，数据 `/var/lib/p2wlan`，管理命令 `/usr/local/bin/p2wlan-server`。可以用 `P2WLAN_SERVER_ROOT`、`P2WLAN_SERVER_CONFIG`、`P2WLAN_SERVER_DATA` 指向隔离测试目录。

## 从 Actions 或 Release 手动上传

服务端构建 workflow 会在构建成功后上传两个架构的 artifact。下载某次 Actions run 的包：

```bash
gh run download RUN_ID --repo yhan-sun/p2wlan --pattern 'p2wlan-server-linux-amd64-*'
find . -name 'p2wlan-server-linux-amd64.tar.gz' -print
```

也可以直接使用已发布的服务端 Release。下面的命令会自动识别远端 `uname -m`，下载对应架构，并在本地和远端各校验一次 `.sha256`：

```bash
./scripts/deploy-server.sh \
  --host 47.109.40.237 \
  --user deploy \
  --version server-v0.1.162 \
  --identity "$HOME/.ssh/ali.pem" \
  --start
```

如果使用 Actions 下载的本地包，指定归档文件即可；同目录的 checksum 文件必须存在：

```bash
./scripts/deploy-server.sh \
  --host 47.109.40.237 \
  --user deploy \
  --archive ./p2wlan-server-linux-amd64.tar.gz \
  --start
```

不使用 key 时省略 `--identity`：

```bash
./scripts/deploy-server.sh --host server.example.com --user ubuntu \
  --version server-v0.1.162 --start
```

脚本会依次执行 SSH 连接、远端临时目录创建、归档校验、安装/更新、版本校验、systemd 启动和 `/health` 检查。首次安装前需要先把 `control.env`、`relay.env`、DNS、TLS 和 Relay catalog 配置好；如果只想安装而暂不启动，去掉 `--start`，脚本会明确报告健康检查已跳过。可先用 `--dry-run` 查看计划，不会连接或写远端：

```bash
./scripts/deploy-server.sh --host server.example.com --user ubuntu \
  --version server-v0.1.162 --dry-run
```

## 让服务器自行拉取

服务器已经安装过 `/usr/local/bin/p2wlan-server` 时，不需要把归档经过本机转发：

```bash
./scripts/deploy-server.sh --mode fetch \
  --host 47.109.40.237 --user deploy \
  --version server-v0.1.162 --start
```

等价的远端命令如下，适合已经 SSH 登录服务器的用户：

```bash
sudo p2wlan-server update --version server-v0.1.162
sudo p2wlan-server verify --service all
sudo p2wlan-server start --service all
sudo p2wlan-server check --service all
```

`update` 会通过 HTTPS 下载与服务器架构匹配的包，校验 checksum 后把版本放进独立目录，更新 `current` 链接，并保留配置、数据库和密钥。服务器自行拉取只适合已有 manager 的安装；新机器先按“安装”章节上传 Release 包，或先运行 `install-server.sh`。

## 初始化配置

`p2wlan-server init` 创建专用 `p2wlan` 用户、配置文件和数据目录。首次生成的 control 配置包含随机 `JWT_SECRET`；该文件权限为 0600，不能提交到 Git 或写入 CI 日志。

```bash
sudo p2wlan-server init --role all
sudoedit /etc/p2wlan/control.env
sudoedit /etc/p2wlan/relay.env
```

生产环境必须配置 HTTPS 反向代理、Relay TLS、DNS/证书、`RELAY_CATALOG_JSON`、Relay 票据签发密钥和对应的 relay 验签 keyring。`RELAY_ALLOW_INSECURE_PLAINTEXT=true` 只允许隔离开发测试，不能用于公网。

如果使用 systemd，管理器会安装 `p2wlan-control.service` 和 `p2wlan-relay.service`：

```bash
sudo systemctl enable --now p2wlan-control.service p2wlan-relay.service
sudo p2wlan-server status
sudo p2wlan-server logs control
```

手动启停和验收命令：

```bash
sudo p2wlan-server start --service all
sudo p2wlan-server stop --service all
sudo p2wlan-server restart --service all
sudo p2wlan-server verify --service all
sudo p2wlan-server check --service all
```

`verify` 只检查当前版本链接和二进制身份；`check` 还要求 systemd 服务处于 active，并检查 control 的 `/health`（Relay 必须配置 loopback metrics，检查撤权就绪 `/readyz`；`all` 同时检查两个服务）。公网反向代理也应单独验证：

```bash
curl -fsS https://control.example.com/health
```

## GitHub Actions staging

在仓库的 **Actions → Build and stage server → Run workflow** 中勾选 `deploy_staging`，然后选择：

- `smoke-upload`：上传两个架构包，只在远端临时高端口启动 control/relay 做 checksum、版本和 `/health` smoke，不触碰正式安装。
- `install-upload`：上传匹配远端架构的包，安装或更新 `/opt/p2wlan-server`，启动 systemd，并执行 `verify`/`check`。
- `remote-fetch`：不上传包，让远端已有 manager 按 `server_version` 从 GitHub Release 拉取、校验、更新并检查。

staging Environment 需要配置：

```text
Variables: STAGING_HOST=47.109.40.237, STAGING_USER=deploy, STAGING_PORT=22
Secrets:   STAGING_SSH_PRIVATE_KEY, STAGING_KNOWN_HOSTS
```

`STAGING_SSH_PRIVATE_KEY` 必须是 CI 专用部署 key，`STAGING_KNOWN_HOSTS` 必须来自人工核验的主机指纹；workflow 固定 `StrictHostKeyChecking=yes`，不执行无条件的 `ssh-keyscan`。`install-upload` 和 `remote-fetch` 还要求 staging 用户可以无交互执行受限的 `sudo`，否则 runner 无法输入服务器密码，会在变更前失败。完整的凭据范围、隔离端口和清理规则见 [`docs/staging-validation.md`](staging-validation.md)。

服务端版本可独立检查：

```bash
/opt/p2wlan-server/current/p2wlan-control --version
/opt/p2wlan-server/current/p2wlan-relay --version
curl -fsS http://127.0.0.1:18080/health
```

服务端监听端口和公网暴露策略由 `control.env`、`relay.env` 及反向代理配置决定。防火墙只开放实际使用的 TCP/UDP 端口，管理端口不要直接暴露给公网。
