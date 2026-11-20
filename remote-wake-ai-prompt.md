# P2WLAN Windows 远程开机：AI 实施提示词

> 用途：交给具备仓库读写、终端和测试执行能力的 AI 代理，一次性完成分析、实现、测试、提交和推送。
>
> 使用方式：新开一个会话，工作目录设为仓库根目录，把「主提示词」整段粘贴进去。中途上下文用完时，用「续跑提示词」；想让它先自查一轮，用「自审提示词」。
>
> 这是本地工作草稿，不是产品文档，不要提交到 `docs/` 或仓库历史里。

---

## 一、主提示词

````markdown
你是 P2WLAN 仓库的资深全栈工程师，负责端到端交付“Windows 远程开机（Wake-on-LAN）”。工作目录是当前仓库根目录。目标不是写 demo，而是可合并、可测试、可上线的完整实现。

# 0. 铁律

- 先读仓库契约，再动手：AGENTS.md、skills/p2wlan-repository/SKILL.md、docs/README.md、docs/ 下全部 Markdown。
- 先分析，再实现；分析结论放在最终回复和 PR 描述里，不要新建 docs/ 过程文档、阶段报告或交接记录。
- 不覆盖工作区已有改动；开始前必须运行 `git status --short --branch`。
- 不伪造测试结果；没跑的命令、没做的真机验收必须明确写“未运行/未完成”。
- 不提交 target/、build/、.dart_tool/、日志、截图、密钥、真实 IP/域名/主机名/用户目录。
- 不为了过门禁删除测试、放宽阈值或跳过检查。
- 遇到设计冲突，先给证据再改方案；不要静默偏离下面的“设计基线”。
- 每完成一个阶段，给我一条简短进度：改了什么、跑了什么测试、下一步是什么。
- 先输出一段不超过 30 行的分析与实施顺序，然后立即开始，不要等待我确认。

# 1. 现状速查（需自行复核，不要只信这段）

- Control：Go + SQLite，`server/`。设备注册、房间、设备可见性、在线租约 `DeviceOnlineTTL = 15s` 在 `server/database/devices.go`。
- 设备能力：`PeerCapabilities`（`server/database/devices.go`），注册时声明，服务端持久化。
- WebSocket：`server/signaling/signaling.go`，只发“有信号/名册变化”的唤醒提示，不承载业务；daemon 对未知消息类型会断开连接。
- 信令队列：`signals` 表由 ICE 逻辑消费；旧 daemon 对未知 signal type 会 `TerminalRejected` 并消费掉，**绝对不能复用来下发唤醒命令**。
- daemon：Rust，`client/daemon/`；控制面客户端在 `client/daemon/src/control/`；本地诊断 HTTP 在 `client/daemon/src/diagnostics/`。
- 物理网卡：`client/netbind/` 已有 `resolve_route`、`bind_udp(addr, Some(interface))`、`if_addrs`，Windows 已启用 IpHelper/Ndis 特性；**MAC 枚举还没有**。
- Windows 服务：`client/daemon/src/main/windows_lifecycle.rs` 已支持 `--windows-service`，但目前只有验收脚本在用，产品安装器没有创建服务。
- Windows 登录自启：`apps/flutter_client/lib/core/platform/desktop_startup_registration.dart` 写 `HKCU\...\Run`，只保证登录后启动。
- Flutter：`apps/flutter_client/lib/`，设备页在 `features/nodes/`，房间/Control API 在 `core/rooms/room_api.dart`、`core/api/control_api.dart`。
- OpenWrt：`docs/guides/openwrt.md` 明确 `room connect` 的房间实例重启后需手工重连，procd 只管个人网络。

# 2. 设计基线（除非发现硬阻塞，不要改）

## 2.1 总体

- 关机/休眠的 Windows 收不到数据面流量，唯一可行路径是 **同局域网常在线代理发魔术包**。
- 触发走 Control HTTPS，不要求请求方先连上 VPN；代理通过已有的设备凭据轮询任务。
- 代理可以是 OpenWrt 路由器、NAS、树莓派或常开 PC；必须是同广播域。
- `sent` 只代表“魔术包已交给 LAN”，**不代表已开机**；真正成功以目标重新注册、`online=1` 为准。

## 2.2 数据模型

统一用 `wake_targets`，设备自报和手填 MAC 共用一张表：

```sql
CREATE TABLE wake_targets (
  id                          TEXT PRIMARY KEY,
  network_id                  TEXT NOT NULL,
  owner_user_id               TEXT NOT NULL,
  kind                        TEXT NOT NULL CHECK(kind IN ('device','manual')),
  device_id                   TEXT,              -- kind=device 时指向 devices
  name                        TEXT NOT NULL,
  mac                         TEXT NOT NULL,     -- aa:bb:cc:dd:ee:ff，规范化
  nic                         TEXT NOT NULL DEFAULT '',
  preferred_agent_device_id   TEXT NOT NULL DEFAULT '',
  enabled                     INTEGER NOT NULL DEFAULT 1,
  created_at                  INTEGER NOT NULL,
  updated_at                  INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_wake_targets_device ON wake_targets(device_id) WHERE device_id IS NOT NULL;

CREATE TABLE wake_jobs (
  id                     TEXT PRIMARY KEY,
  network_id             TEXT NOT NULL,
  wake_target_id         TEXT NOT NULL,
  target_mac             TEXT NOT NULL,          -- 创建时快照
  agent_device_id        TEXT NOT NULL,
  agent_registration_seq INTEGER NOT NULL,       -- fencing
  requester_user_id      TEXT NOT NULL,
  state                  TEXT NOT NULL CHECK(state IN ('queued','claimed','sent','failed','expired')),
  reason                 TEXT NOT NULL DEFAULT '',
  attempts               INTEGER NOT NULL DEFAULT 0,
  created_at             INTEGER NOT NULL,
  expires_at             INTEGER NOT NULL,
  claimed_at             INTEGER NOT NULL DEFAULT 0,
  finished_at            INTEGER NOT NULL DEFAULT 0
);
```

- 代理能力用 `devices.wake_proxy INTEGER NOT NULL DEFAULT 0`，**只能由设备注册声明写入**，用户 JWT 不能把任意设备标成代理。
- MAC 不进 `devices` 的 JSON、不进 `/nodes` 响应、不进路径遥测、不进日志/支持包。只允许设备本人、房间 owner、被指派代理在 claim 时读取。

## 2.3 API

| 方法 | 路径 | 认证 | 说明 |
| --- | --- | --- | --- |
| PUT | `/api/v1/devices/{id}/wake` | device token，仅自己 | 自报 `{mac,nic}`，upsert device 类型 target |
| DELETE | `/api/v1/devices/{id}/wake` | device token | 关闭并删除该 target |
| GET | `/api/v1/devices/{device}/wake` | 用户 JWT | 能力/状态，给 UI |
| POST | `/api/v1/devices/{device}/wake` | 用户 JWT | 触发；body 可带 `agent_device_id` |
| GET/POST | `/api/v1/networks/{network}/wake-targets` | 用户 JWT | 手填 MAC 目标列表/创建 |
| PATCH/DELETE | `/api/v1/wake-targets/{id}` | 用户 JWT | 修改/删除；manual 目标仅 owner |
| GET | `/api/v1/wake/jobs/{id}` | 用户 JWT 或被指派代理 | 状态 |
| GET | `/api/v1/wake/jobs?state=queued&limit=4` | device token | 代理拉任务 |
| POST | `/api/v1/wake/jobs/{id}/claim` | device token | 原子领取，返回 `{mac, expires_at}` |
| POST | `/api/v1/wake/jobs/{id}/result` | device token | `{state:"sent"|"failed", reason}`，幂等 |

授权复用 `ListVisibleDevices` 的语义：个人网络按 `user_id`，房间按成员 + `room_device_access`；`blocked/pending` 设备不能作为目标。manual 目标只允许创建者和房间 owner 触发。

## 2.4 选代理

1. body 指定 → 必须是同 network、`wake_proxy=1`、`last_seen <= 15s` 的设备。
2. 只有一个候选 → 直接用。
3. target 有 `preferred_agent_device_id` → 用。
4. 否则返回 `409 wake_agent_ambiguous` + 候选列表，让 UI 选。
5. 无候选 → `409 wake_agent_unavailable`。

**同房间 ≠ 同局域网**：Control 不能推断 LAN 共处；MVP 必须让用户选一次。P2 可加 LAN 指纹自动分组（服务端下发 per-network salt，只上报 `HMAC(salt, 网关MAC)`，绝不上报原始网关 MAC）。

## 2.5 限额、幂等、过期

- 每目标 10s 内 1 次、每分钟 6 次；每用户每分钟 10 次；超出 `429 wake_rate_limited`。
- 每目标最多 4 个活跃任务，每网络 32 个；队列必须有界。
- 30s 内对同一目标重复请求返回已有 job，不新建。
- job TTL 30s；claim 租约 10s；允许在租约过期后重新 claim，最多 2 次。
- claim 必须校验 `agent_device_id` + `agent_registration_seq` 当前值；result 必须校验状态为 `claimed` 且是同一代理。
- 完成行 7 天后清理。
- 类型化 reason：`no_agent`、`agent_offline`、`already_online`、`target_no_mac`、`target_blocked`、`send_failed`、`no_lan_interface`、`unsupported_platform`、`rate_limited`、`expired`。

# 3. 实现范围

## 3.1 必须做（P0 + P1 + P2）

**P0：先验证硬件链路**
- 在 `p2pnet-netbind` 增加 `list_lan_interfaces()`：IPv4/netmask/broadcast 用 `if_addrs`；MAC 按平台取（Windows `GetAdaptersAddresses`，Linux `/sys/class/net/<n>/address`，macOS `getifaddrs` 的 `AF_LINK`）；排除 loopback、daemon 自己的 TUN、`utun/tun/tap/docker/veth` 等虚拟接口；能拿到链路状态更好。
- daemon 增加 `p2wlan wake send --mac AA:BB:CC:DD:EE:FF [--interface eth0]`，不经过 Control，用于真机验证。
- 魔术包：`6×0xFF + MAC×16`，UDP 端口 9 和 7，每个接口各发 3 次、间隔 100ms；用 `bind_udp` 绑接口，目标用该接口的定向广播（`ip | ~mask`），不要只发 `255.255.255.255`。
- 新增 Windows 诊断/配置脚本 `scripts/windows/enable-wol.ps1`：默认只读检查（网卡、`powercfg /devicequery wake_armed`、快速启动、休眠状态），`-Apply` 才修改；修改前必须打印将要做的变更。

**P1：控制面 + 代理 + 客户端**
- Go：迁移、`wake_targets`/`wake_jobs` 存储、handlers、路由、限流、测试。
- Rust：`wake.proxy` / `wake.allow_remote` 配置；注册声明 `wake_proxy_v1`；注册后自报有线网卡 MAC；新增非 critical 的 wake 任务循环（5s 轮询，单次 HTTP 超时，失败退避，退出取消，不持锁做网络 I/O）；执行器本机限流（每分钟 8 次，同 MAC 5s 内不重复）；本地诊断 `/wake` 只暴露状态，不暴露 IP/MAC。
- Flutter：设备页/房间设备行增加“远程开机”，按 `在线 / 离线有MAC有代理 / 离线无MAC / 离线无代理` 四态显示；触发后轮询目标在线状态最多 120s；多代理弹选择并记住首选；中英文文案。
- CLI：`p2wlan wake status`、`p2wlan wake proxy on|off`、`p2wlan wake target add|list|remove`。

**P2：Windows 自动上线（重点）**
- 目标：Windows 开机后**无需用户登录**即可恢复 p2wlan 设备身份并上线。
- 分析现有 `--windows-service` 路径和 `scripts/windows_lifecycle/windows_lifecycle_acceptance.ps1` 的服务用法，补齐产品化：
  - 安装/卸载/查询：`p2wlan service install|uninstall|status`（或 Flutter 设置页的“开机自启（服务）”开关，需要 UAC）。
  - 服务使用机器级配置：`%ProgramData%\p2wlan\`，ACL 只给 SYSTEM + Administrators；日志/状态同目录。
  - 设备身份迁移：安装时用户在场且已提权，明确告知后把用户配置中的设备身份迁移到机器级配置；不得把用户密钥复制到 Users 可读路径。
  - 服务账户 LocalSystem，启动完整 daemon（TUN + Control）；如果 Wintun 在 session 0 不可用，必须先给出证据，再实现只做 wake-proxy 的服务模式并在文档中说明“目标机仍需登录才上线”的边界。
  - 不实现 Windows `AutoAdminLogon` 明文密码自动登录；不把账户密码写入注册表或配置文件。
- 保留现有 HKCU 登录自启，不破坏托盘/单用户流程。

**P2：手填 MAC 目标**
- 覆盖没有装 p2wlan 的机器；owner 创建，成员不可见（或按你的安全判断收紧），不泄露 MAC。

## 3.2 可选增强（做不完必须在报告中列出，不许假装完成）

- LAN 指纹自动选代理。
- WS `wake_available` 提示（必须做能力协商，旧 daemon 不能收到未知消息）。
- “打开房间时自动唤醒目标”。
- 管理台只读展示唤醒任务（不含 MAC）。

## 3.3 明确不做

- SecureOn 密码、WoWLAN、vPro/IPMI、路由器端口映射 + DDNS。
- Windows 交互式自动登录（明文密码）。
- 任何形式的“服务端直接发魔术包”。

# 4. 兼容性与质量要求

- 旧 daemon 连新 Control、新 daemon 连旧 Control 都不能崩：新增注册字段可选；wake 接口 404 时降级为“不支持”，不要阻塞主流程。
- DB 迁移幂等，旧库可直接打开。
- 生产路径不得 panic；网络/磁盘/用户输入失败用类型化错误和稳定 reason code。
- 新增队列/任务必须有容量、TTL、取消条件；禁止无限增长和静默丢弃。
- 不持锁做网络 I/O、sleep、外部回调。
- 不新增重型依赖；MAC 枚举优先用现有 `if-addrs`/`libc`/`windows-sys`。新增依赖必须说明理由。
- 不改现有 Direct/Relay/信令语义；不复用 `signals`。
- MAC 规范化并校验：6 字节、单播、非全零、非广播；拒绝多播位。

# 5. 测试与门禁

每完成一个阶段，先跑该阶段测试，再提交。最终必须运行（以 `.github/workflows` 的实际命令为准，若不同请在报告中说明）：

```sh
git diff --check
python3 scripts/docs/verify_repository.py
python3 scripts/quality/check_code_health.py --base-ref main
python3 -m unittest discover -s scripts/quality/tests -p 'test_*.py'
bash -n scripts/install-server.sh scripts/deploy-server.sh scripts/p2wlan-server
cd server && go test ./...
cargo test --workspace
cd apps/flutter_client && flutter analyze && flutter test
```

最低测试覆盖：

- Go：任务状态机、claim 原子性、`registration_seq` fencing、过期、重复 result 幂等、跨网络/跨用户越权、限流、MAC 不出现在 `/nodes` 和遥测。
- Rust：魔术包字节、广播地址计算、排除 TUN/虚拟网卡、无 LAN 接口的类型化失败、限流、job 领取/结果幂等、无锁跨 I/O。
- Flutter：四态 UI、代理选择、超时文案、中英文。
- PowerShell：`enable-wol.ps1` 只读模式不修改系统；`service install/uninstall` 脚本幂等。

真机验收（AI 做不了，必须写成未完成 + 手工清单）：
- Windows S5/S4/S3 + 有线；路由器 `tcpdump -i br-lan -X 'udp port 9'` 能看到魔术包；`powercfg /devicequery wake_armed`；服务安装后重启，未登录时 Control 能看到设备上线。

# 6. 文档

- 新增 `docs/guides/remote-wake.md`：Windows BIOS/网卡/快速启动/有线要求、代理部署、限制、排障；命令必须真实可执行，示例只用 `example.com` 和占位符。
- 更新 `docs/reference/cli.md`、`docs/reference/configuration.md`、`docs/explanation/security-model.md`（MAC 处理、服务模式）、`docs/README.md` 索引。
- 不在 docs/ 写阶段汇报、开发过程、事故流水。
- 所有新增/修改文档必须通过 `python3 scripts/docs/verify_repository.py`。

# 7. 提交与推送

- 从当前 main 建分支：`feat/remote-wake`；不要直接在 main 提交。
- 按逻辑分多次提交，信息格式严格 `feat:中文说明`，`feat:` 后不加空格。例如：
  - `feat:增加远程开机网卡枚举与魔术包发送`
  - `feat:实现远程开机控制面任务编排`
  - `feat:实现Windows服务开机自启`
- 每次提交前确认暂存区没有构建产物、日志、密钥。
- 全量门禁通过后推送：`git push -u origin feat/remote-wake`；禁止 force push；推送失败不要反复重试，报告确切错误。
- 推送后给出 `git log --oneline`、远端分支链接和变更摘要。

# 8. 最终交付报告（必须包含）

1. 分析结论：现状、缺口、影响面、威胁模型、最终设计与你做的偏离（如有）。
2. 改动清单：按 Control / daemon / netbind / Flutter / 脚本 / 文档分组，附关键文件路径。
3. 测试结果：每条命令 + 实际结果；失败项要说明是本次引入还是既有问题。
4. 未运行项：真机、重启、公网、安全审计，逐条列出原因。
5. 提交与推送：commit hash、分支、远端链接。
6. 残余风险与后续建议。

# 9. 安全红线（违反即失败）

- 不实现 Windows 账户自动登录，不存储账户密码。
- 不让用户 JWT 把任意设备标成 wake proxy。
- 不让代理发送除魔术包以外的任何东西。
- 不把 MAC 写进日志、遥测、支持包、`/nodes` 响应或管理台普通视图。
- 不把 `sent` 说成“已开机”。
- 不用 `signals` 下发唤醒。
- 不在持锁时做网络 I/O。
- 不提交密钥、真实地址、个人路径、日志、截图。
````

---

## 二、续跑提示词

````markdown
继续上一轮的“P2WLAN Windows 远程开机”实现。

先做：
1. `git status --short --branch`
2. `git log --oneline -15`
3. 查看当前分支未提交改动和上次报告里的“未完成项”

规则：
- 不要重做已完成项；不要覆盖未提交改动。
- 按 P0 → P1 → P2 继续，每完成一个可测试单元就跑对应测试并提交。
- 提交信息仍然是 `feat:中文说明`，`feat:` 后不加空格。
- 如果上下文不足以完成全部，优先保证：代码可编译、测试可运行、提交完整、未完成项写清楚。
- 最后跑全量门禁并推送 `feat/remote-wake`，给出 commit 列表和远端链接。
- 不要伪造测试结果；真机验收未做就写未做。
````

---

## 三、自审提示词

````markdown
对当前 `feat/remote-wake` 分支做一次严格自审，只修问题，不加新功能：

- 对照 AGENTS.md 和设计基线，检查：状态所有权、fencing、队列上限、TTL、类型化错误、锁内 I/O、panic、日志中的 MAC/IP、旧客户端兼容。
- 检查 claim/result 的并发与幂等；检查 job 过期和代理重注册后的旧进程不能领取。
- 检查 Windows 服务安装/卸载的 ACL、配置路径、设备身份迁移；确认没有明文密码。
- 检查 Flutter 四态和超时文案；检查中英文。
- 检查文档命令是否真实可执行、是否包含真实地址/路径。
- 跑全量门禁；修复后按 `feat:中文说明` 提交并推送。
- 输出：发现的问题、修复、测试结果、仍未解决的问题。
````

---

## 四、人工验收清单（AI 不替代）

### 4.1 目标机硬件与系统

- [ ] BIOS/UEFI 开启 `Power On By PCI-E` / `Wake on LAN`，关闭 `ErP Ready` / `EuP` / `Deep Sleep`
- [ ] 网卡高级属性：`Wake on Magic Packet`、`Shutdown Wake-On-LAN`（Realtek）、`Wake on Magic Packet from power off state`（Intel）
- [ ] 电源管理勾选“允许此设备唤醒计算机”“只允许幻数据包唤醒计算机”
- [ ] 关闭快速启动（`powercfg /h off` 或 `HiberbootEnabled=0`）
- [ ] 有线连接；必要时关闭网卡/交换机绿色节能
- [ ] `powercfg /devicequery wake_armed` 能看到网卡
- [ ] 真正执行 `shutdown /s /f /t 0`，不是睡眠

### 4.2 代理与网络

- [ ] 代理与目标在同一广播域（同 VLAN/子网）
- [ ] 路由器上 `tcpdump -i br-lan -X 'udp port 9'` 能看到 102 字节魔术包
- [ ] 代理不是靠 `room connect` 手工维持（或已确认重启后仍在房间）

### 4.3 端到端

- [ ] 目标关机后，App 点“远程开机”，任务从 queued → claimed → sent
- [ ] 目标上电，Windows 启动
- [ ] 未登录时 Control 能看到设备重新注册（服务模式）
- [ ] 若启用了 BitLocker PIN/密码，记录“需要人工解锁”的边界
- [ ] 120s 内未上线时，UI 给出可执行的排障提示

### 4.4 安全

- [ ] 房间普通成员不能唤醒 manual 目标
- [ ] 非代理设备不能 claim 任务
- [ ] 重复点击不会产生大量任务
- [ ] 日志、支持包、`/nodes` 响应中没有 MAC
- [ ] 服务配置文件 ACL 仅 SYSTEM + Administrators

---

## 五、关键决策速查

| 决策 | 结论 |
| --- | --- |
| 唤醒传输 | Control 持久化任务 + 代理 5s 轮询，不走数据面、不复用 `signals` |
| 成功语义 | `sent` = 已发包；上线以目标重新注册为准 |
| 目标 MAC | 目标自报 + 手填 MAC 两种，统一存 `wake_targets` |
| 代理选择 | 单代理自动；多代理用户选并记住；LAN 指纹为增强 |
| MAC 隐私 | 独立表，严格授权，不进日志/遥测/roster JSON |
| Windows 自动上线 | 服务自启 + 机器级配置，不做明文密码自动登录 |
| 旧客户端 | 新字段可选，wake 接口 404 时降级 |
| 真机验收 | AI 只准备脚本和清单，不代跑 |

---

## 六、交付后你应检查的命令

```sh
git status --short --branch
git log --oneline -10
git diff --stat main...HEAD
cd server && go test ./...
cargo test --workspace
cd apps/flutter_client && flutter analyze && flutter test
python3 scripts/docs/verify_repository.py
python3 scripts/quality/check_code_health.py --base-ref main
```

重点看三件事：

1. 有没有为了过测试而删测试/放宽阈值。
2. `/nodes`、日志、支持包里有没有出现 MAC。
3. Windows 服务相关改动有没有把账户密码写进注册表或配置文件。
