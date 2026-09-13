# 自托管：从空目录启动 Control 与 Relay

适用于包含本修复的源码/服务端构建。旧 Release 不会因为文档更新自动获得新命令。现有机器不要覆盖配置、JWT secret、票据签名私钥或数据库；先备份，再按升级章节处理。

## 1. 哪个程序部署在哪里

```text
客户端 A ── HTTPS ──┐
                    ├─ HTTPS 反向代理 ── HTTP loopback/私有容器网 ── Control ── SQLite
客户端 B ── HTTPS ──┘                                             │
                                                                 │ 设备凭证、短期票据
客户端 A ══ UDP 加密直连 ══ 客户端 B                               │
   ╚════ TLS ════ Relay ════ TLS ═══╝                            │
                    └──── 带专用 Bearer 凭证轮询撤权 ────────────────┘
```

- `p2wlan-control`：账号、房间、设备/IP、信令、设备凭证和 Ed25519 Relay 票据。SQLite 只由它访问。
- `p2wlan-relay`：验证票据后转发密文。它不是客户端 daemon，不创建 TUN、不改系统路由，也不需要 Windows GUI 的 UAC 桥接。
- `p2wlan-config`：一次性生成相互匹配的配置与随机秘密。它不是在线服务，不把私钥打印到终端，不覆盖已存在的输出目录。
- 客户端 daemon：运行在需要加入虚拟网络的设备上，负责 TUN、路由、Direct/Relay 选择；只部署 Control/Relay 不会让服务器自动加入房间。

网络边界：公网只开放 Control 的 **HTTPS 443/TCP** 和 Relay 的 **TLS 18081/TCP**。Control 的 HTTP 18080 保持 loopback/私有容器网；Relay 的管理端口 18082 保持 loopback，不发布到公网。UDP observer 是可选的 NAT 辅助服务，本例不启用它；18082/TCP 管理端口不能填进 UDP observer 字段。

Control 与 Relay 分机时，将 `RELAY_REVOCATION_FEED_URL` 改成 Control 的可信 HTTPS 地址 `/api/v1/relay/revocations`。不要跨公网使用明文 HTTP 撤权链路。JWT、设备凭证、Relay 票据和撤权 Bearer token 是不同凭据，不能互相代用。

## 2. 构建与依赖

`server/go.mod` 是源码最低 Go 版本的权威来源，目前为 **1.26.6**；原生构建同样必须满足，不只是 Docker。Dockerfile 使用 1.26.8 且 `GOTOOLCHAIN=local`，不再用 1.23。没有修改 go.mod/go.sum 或业务依赖来迁就旧工具链。

从仓库根目录，在 Linux/macOS shell 构建：

```bash
mkdir -p build/selfhost
cd server
CGO_ENABLED=0 go build -trimpath -o ../build/selfhost/p2wlan-control .
CGO_ENABLED=0 go build -trimpath -o ../build/selfhost/p2wlan-relay ./relay
CGO_ENABLED=0 go build -trimpath -o ../build/selfhost/p2wlan-config ./cmd/p2wlan-config
cd ..
```

Windows PowerShell 原生构建：

```powershell
New-Item -ItemType Directory -Force build/selfhost | Out-Null
$env:CGO_ENABLED = '0'
Push-Location server
go build -trimpath -o ../build/selfhost/p2wlan-control.exe .
if ($LASTEXITCODE -ne 0) { throw 'control build failed' }
go build -trimpath -o ../build/selfhost/p2wlan-relay.exe ./relay
if ($LASTEXITCODE -ne 0) { throw 'relay build failed' }
go build -trimpath -o ../build/selfhost/p2wlan-config.exe ./cmd/p2wlan-config
if ($LASTEXITCODE -ne 0) { throw 'config build failed' }
Pop-Location
```

服务端 SQLite 使用纯 Go 驱动；上述 Linux `CGO_ENABLED=0` 构建不依赖主机的 glibc 动态加载器，也不需要系统 sqlite3 开发库。**这不代表所有旧 Linux 发行版均已验收**。服务端 Go 二进制、Rust daemon、Flutter GUI 的依赖不同；不要把某个客户端的 `GLIBC_x.y not found` 推广成 Control/Relay 必须 Ubuntu 22+。报告兼容性时附：下载的准确文件名、`--version`、`file`、`readelf -l`、`uname -a` 和完整错误。发布构建/宿主内核也会影响可运行范围。

系统部署另需 systemd、bash、curl、openssl、tar、coreutils 和专用 `p2wlan` 用户；Windows 原生仅需对应 exe、证书和环境配置。Docker Desktop 必须使用 **Linux containers**，不是 Windows 容器。新 Dockerfile 包含 Control、Relay 和配置工具，默认入口仍是 Control。

## 3. 本机隔离验证：先验证配置，不涉及公网与真实客户端

从仓库根目录运行（Windows 将工具名称加 `.exe`）：

```bash
build/selfhost/p2wlan-config --output deploy/selfhost/config --dev-localhost
python3 scripts/selfhost/run-native.py control --config-dir deploy/selfhost/config --bin-dir build/selfhost
```

另开一个终端：

```bash
python3 scripts/selfhost/run-native.py relay --config-dir deploy/selfhost/config --bin-dir build/selfhost
```

Windows 可使用对应 PowerShell 启动器：

```powershell
./scripts/selfhost/run-native.ps1 -Role control -ConfigDirectory deploy/selfhost/config -BinaryDirectory build/selfhost
# 另一个终端执行：
./scripts/selfhost/run-native.ps1 -Role relay -ConfigDirectory deploy/selfhost/config -BinaryDirectory build/selfhost
```

**不要 `source control.env` 或 `eval` 文件内容**；文件中 JSON 是字面值，Shell 会吃掉其引号。上面的启动器和 Compose 会保留原始 JSON。

验证端口：

```bash
curl -fsS --max-time 5 http://127.0.0.1:18080/health
curl -fsS --max-time 5 http://127.0.0.1:18082/readyz
```

`--dev-localhost` 生成有效期 24 小时、仅覆盖 loopback 的自签名测试证书，不会安装系统信任、开放公网或关闭客户端证书检查。正式客户端默认不信任它。它只用于本机服务端验证；不要用 `-k`、禁用 TLS 验证或开放 plaintext 来解决正式部署问题。

完整自动化验证：

```bash
go run scripts/selfhost/smoke.go --bin-dir build/selfhost
```

它在临时目录和动态 loopback 端口中生成配置、启动两个真实进程，执行账号注册、设备挑战签名、票据签发、TLS 认证与 Relay 转发，再删除设备验证撤权断连。结束时回收自己启动的进程。它不等于真实客户端 TUN、打洞或公网可达性验收。

## 4. Docker Compose

这是独立配置，不要拿 native 配置直接挂进容器，里面路径/撤权地址不同。`config` 目录已存在时，先停止使用它的服务；保留旧配置做备份，选择新测试工作目录，而不是盲目删除在线部署的秘密。

新工作区示例：

```bash
build/selfhost/p2wlan-config --mode docker --output deploy/selfhost/config --dev-localhost
docker compose --env-file deploy/selfhost/config/compose.env -f deploy/selfhost/compose.yml config --quiet
docker compose --env-file deploy/selfhost/config/compose.env -f deploy/selfhost/compose.yml up -d --build --wait
docker compose --env-file deploy/selfhost/config/compose.env -f deploy/selfhost/compose.yml ps
```

Windows Docker Desktop 可使用相同 Compose 参数；配置生成器使用 `.exe`。Linux 生成器记录运行用户 UID/GID（root 生成时将容器数据文件交给 UID/GID 10001），容器以该非 root 用户运行。不要省略 `--env-file`，否则 UID 与 bind-mount 文件权限可能不匹配。

数据位于 `deploy/selfhost/config/data`，证书、密钥和 env 文件都在 gitignore 的 config 下。服务容器只读根文件系统、无 Linux capabilities、禁止提权；只挂载需要的 TLS 文件和数据，不把 Docker socket 或整个宿主目录放进去。

Relay readiness：

```bash
docker compose --env-file deploy/selfhost/config/compose.env -f deploy/selfhost/compose.yml exec relay curl -fsS --max-time 5 http://127.0.0.1:18082/readyz
```

停止测试：使用相同参数执行 `down`。本例使用 bind mount，停止不会自动删除数据；不要将日志、配置文件或 `docker compose config` 的完整输出上传到 Issue，它们可能包含秘密。

## 5. 公网部署：真实域名与可信 TLS

先准备 Relay 域名及匹配的可信证书链/私钥，证书 SAN 必须覆盖客户端实际连接的名字。再在**全新输出目录**生成配置：

```bash
build/selfhost/p2wlan-config --mode docker --output deploy/selfhost/config \
  --relay-endpoint tls://relay.example.com:18081 \
  --tls-cert /secure/relay-fullchain.pem --tls-key /secure/relay-privkey.pem
```

生成器验证证书/私钥匹配、SAN 和有效期；它不能替代客户端验证完整 CA 信任链。对于组织内部 CA，需要正确安装组织信任链，而不是禁用验证。生成器复制 TLS 文件，不跟踪原 ACME 文件：证书续期后应安全更新 `config/tls.crt` 与 `config/tls.key`，保持权限，并重建 Relay 容器以重新加载 bind mount 和证书。

编辑 `config/compose.env` 的 `RELAY_PUBLISH_HOST=0.0.0.0` 才会发布 Relay；默认只在本机可访问。用可信 HTTPS 反向代理发布 `control.example.com` 至 `127.0.0.1:18080`，保留 WebSocket Upgrade 和正确的请求超时。不要直接发布 Control 明文端口。客户端填写 `https://control.example.com`，不是 Relay 地址。

例如 Caddy 的独立配置片段（先按其官方部署文档安装并配置 DNS/ACME）：

```caddyfile
control.example.com {
    reverse_proxy 127.0.0.1:18080
}
```

反向代理会改变来源 IP。仅当需要转发来源地址用于限流时，设置 `CONTROL_TRUSTED_PROXY_CIDRS` 为该代理的精确 CIDR；不要写 `0.0.0.0/0`。Docker 端口转发可能改变实际来源，先核对日志再配置，不能假设来源一定是 127.0.0.1。浏览器 CORS 与原生客户端连接无关，不要为 Flutter 桌面随意放开 Origin。

## 6. 必需配置与关系

| 进程 | 变量 | 语义与本例值 |
| --- | --- | --- |
| Control | `CONTROL_BIND` / `PORT` | `CONTROL_BIND` 优先；native 为 `127.0.0.1:18080`，容器内 `:18080`。不设置 bind 时保留 PORT/8080 的兼容默认 |
| Control | `DB_PATH` | 数据库**文件**路径，不是目录；容器 `/data/p2pnet.db`。缺失的普通父目录创建为私有目录；不能绕过挂载权限 |
| Control | `LOG_UPLOAD_DIR` | 持久化支持日志目录；本例 `/data/log-uploads`，不要依赖工作目录 |
| Control | `JWT_SECRET` | 每个部署独立随机值，持续保存，改动会影响账号会话；不是 Relay Ed25519 私钥 |
| Control | `RELAY_CATALOG_JSON` | 数组；每项包含 `region`、唯一 `audience`、客户端能解析访问的 `tls://host:port`。不能发布 `0.0.0.0` 或内部容器名 |
| Control | `RELAY_TICKET_SIGNER_JSON` | 生成器写入 active kid 和 **32 字节 seed 的 64 字符十六进制值**。文件权限受保护；不要写入命令行或输出日志 |
| Control | `RELAY_TICKET_SIGNER_KEY_FILE` + `RELAY_TICKET_SIGNER_KID` | 可替代 inline JSON 的 Ed25519 PKCS#8 PEM 模式，两项一起配置；文件模式优先 |
| Control | `RELAY_TICKET_TTL` | 默认 5m，允许 30s–15m。不是 JWT 账号 token 的 TTL |
| 两者 | `RELAY_REVOCATION_FEED_TOKEN` | 必须完全相同的专用随机 Bearer 凭据；不同于 JWT_SECRET、设备 token 和票据 |
| Relay | `RELAY_BIND` | 本机监听地址，本例容器 `:18081`；与目录中的公开 endpoint 区分 |
| Relay | `RELAY_TLS_CERT` + `RELAY_TLS_KEY` | 完整证书链和匹配私钥路径，必须成对；不是签票 Ed25519 密钥 |
| Relay | `RELAY_TICKET_KEYRING_JSON` | `{kid: public_key_hex}`，必须匹配 Control signer 的 kid 和 32 字节公钥；不能把 seed 当公钥 |
| Relay | `RELAY_AUDIENCE` / `RELAY_REGION` | 与目录中的 audience/region 完全一致 |
| Relay | `RELAY_REVOCATION_FEED_URL` | native 同机 loopback；Docker `http://control:18080/api/v1/relay/revocations`；分机公网必须 HTTPS |
| Relay | `RELAY_REVOCATION_POLL_INTERVAL` | Go duration，本例 5s；默认 30s，不是整数毫秒 |
| Relay | `RELAY_METRICS_BIND` | 本例 `127.0.0.1:18082`。`/healthz` 仅存活，`/readyz` 校验当前撤权同步可用性；不对公网暴露 |
| Relay | `RELAY_REQUIRE_AUTH` | 保持 true |
| Relay | `RELAY_ALLOW_LEGACY_UNAUTH` / `RELAY_ALLOW_INSECURE_PLAINTEXT` | 本例均 false，不能为绕过配置错误而启用 |

目录示例（不是可直接启动的完整密钥配置）：

```json
[{"region":"selfhost","audience":"selfhost-relay-1","endpoint":"tls://relay.example.com:18081"}]
```

可选项：`RELAY_UDP_OBSERVER_BIND` 是 UDP observer 监听地址，配套目录中的 `udp_observer_endpoint` / `udp_observer_endpoints` 必须是客户端可访问的 UDP 地址。默认不启用；不要因未配置 observer 就声称 Relay 不可用。队列、超时、连接上限及拒绝限流参数见 `server/relay/config.go`；`RELAY_DEBUG_FRAMES`、`RELAY_FORWARD_DELAY_MS` 属于诊断，不应盲目用于生产。

不配置 Relay 目录和签名器时，Control 可用于无中继能力的开发场景；但显式填错目录、只填目录不配签名器、配签名器却给空目录都会启动失败，不再静默运行成看似健康的无 Relay 服务。

## 7. 健康检查、错误和升级

`p2wlan-server check --service all` 现在同时验证 Control 和 Relay；Relay 没有 metrics 地址、撤权未就绪或 HTTP 失败都会返回非零，不再只看 Control `/health`。管理器使用有界 HTTP 超时。旧 Relay 没有 `/readyz`：升级管理器时要连同新服务二进制部署，不能只复制脚本。

首次撤权同步完成前 Relay 返回 503；超过 `3 × poll_interval + 10s` 没有成功完成同步时也不可就绪。保留到期拒绝与连接撤权，不以 `/healthz=200` 替代它。同步版本、游标与最近成功时间在 `/metrics` 中，可与 Control HTTP 状态一起诊断。

| 现象 | 先检查 |
| --- | --- |
| `go.mod requires go >= ...` | Docker build stage 与本地 `go version`，不要只改运行镜像 |
| 数据库 `... (14)` | SQLite 14 是无法打开文件，不是内存耗尽的充分证据。检查 DB_PATH 是文件、父目录可写、挂载类型、服务用户，以及 -wal/-shm 能否在同目录创建 |
| `prepare database parent directory` / `not a regular file` | 路径中某级是文件，或把宿主目录当成 db 文件挂载；使用目录 volume 并追加 `p2pnet.db` |
| Control 健康但 tickets 503 | signer/catalog 配置、kid、设备凭证；不能用账号 JWT 代替设备凭证请求 Relay 票据 |
| Relay `/healthz=200`、`/readyz=503` | 撤权 URL、HTTP 状态、专用 token、Control 可达性与同步版本；不是“服务已经可用” |
| TLS 证书加载/验证失败 | 证书与 key 成对、文件权限、完整链、SAN、有效期；TLS 与签票私钥不要混淆 |
| 支持日志上传失败 | `LOG_UPLOAD_DIR` 的绝对路径、可写性和磁盘空间；systemd 已设置数据目录为 WorkingDirectory |
| Ubuntu 20.04 失败 | 区分服务端/daemon/GUI 包、架构、动态依赖和内核；不能仅凭系统名称归因 |

数据库目录应位于支持 SQLite WAL 锁语义的本地持久文件系统，不建议网络共享盘。`DB_PATH` 的 SQLite URI/`:memory:` 仅保留兼容语义，不由普通路径预检创建目录；生产使用明确普通文件路径。

已有部署升级不要重新运行配置生成器覆盖密钥。保存现有 JWT/票据签名私钥和撤权 token；修正必需变量，增加 loopback metrics，再升级 Control/Relay 二进制。所有路径变更先停服务并备份数据库及 WAL，验证权限后启动。证书续期和票据密钥轮换是两个不同流程。系统包上传、版本切换及受控 staging 见 [server-deployment.md](server-deployment.md)。

参考：[Go 发布记录](https://go.dev/doc/devel/release)、[Go Linux 基线](https://go.dev/wiki/Linux)、[SQLite 错误码](https://www.sqlite.org/rescode.html)、[Compose 环境文件](https://docs.docker.com/reference/compose-file/services/#env_file)。本文的自动化验收不代替用户原故障机或公网双端验证。
