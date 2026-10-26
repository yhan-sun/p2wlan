# 工程质量与架构边界

P2WLAN 的工程目标不是追求文件数量或抽象层数，而是让网络状态、故障边界和发布行为可以被独立推理、测试和审查。本页定义长期稳定的代码组织规则；具体协议字段和运行参数仍以对应 reference 文档与源码为准。

## 设计原则

### 单一状态所有者

一个会影响连接正确性的事实只能有一个权威所有者。其他模块可以持有带版本或 generation 的不可变快照，但不能维护第二份可独立演进的真相。

典型状态包括：

- peer 在线状态与 incarnation；
- network generation；
- WireGuard transport session；
- Direct/Relay active path；
- UDP publication/socket identity；
- DPLPMTUD business budget；
- room membership 与发送授权。

跨异步边界传递快照时必须同时传递足够的 fencing identity，并在真正产生副作用前再次验证。禁止依赖“刚才还是当前状态”这一隐含假设。

房间内的原生 overlay REQUEST 在首次进入回程处理时，以 try-only 方式取得原发送许可。该许可随原输入穿过等待、TUN 路由、队列与加密；路由不能重新取得续租后的许可。撤权、重授权、缩短租期或原许可到期后，旧输入和旧密文不能借用新许可。原输入只弱引用房间所有者，不能延长其生命周期。

实际 Direct 写入前复核当前房间快照与原许可，并仅在原有非阻塞写入期间保留该快照；Relay 在原 writer 开始写入前复核，该核验不证明许可在后续异步 Full 期间始终有效。ACK 最终仍由唯一 PeerManager 事务核验原 Full、当前会话/路径/房间与原许可到期后消费一次信用。缺少原许可、所有者变化或锁竞争均不得产生成功信用。这些规则不把 MockTun 注入或系统 socket 观察提升为真实系统 TUN 读取证明。

### 明确的数据面阶段

业务包的生命周期按职责拆成路由、排队、加密、路径选择、发送和接收验证。模块不能为了方便同时成为多个阶段的权威状态所有者。

控制包、探测包和业务包可以共享底层 transport，但必须保持独立的调度语义。任何可能改变 WireGuard counter 顺序、replay window、Direct/Relay fallback 或 MTU 预算的修改，都属于协议正确性修改，必须带针对竞态或时序的回归测试。

### 有界资源

所有长期运行的队列、缓存、重试和后台任务都必须回答四个问题：

1. 最大容量是多少；
2. 最长生命周期是多少；
3. 取消条件是什么；
4. 丢弃或失败如何被观测。

不允许无限 channel、无限重试、无 deadline 的等待或静默丢包。重试不能掩盖真实故障；如果交付状态不确定，必须 fail closed，而不是把同一密文换路径重放。

### 锁不跨不受控等待

默认不允许在持有互斥锁或写锁时执行网络 I/O、sleep、外部回调或没有明确上界的 await。确实需要跨 await 保持锁来维护协议顺序时，锁必须是该顺序的显式所有者，并且等待有 deadline、注释解释不变量、测试覆盖超时和取消路径。

### 错误是 API 的一部分

预期失败使用结构化错误、枚举或稳定 reason code 表示；日志文本不是状态机接口。错误必须在最靠近事实拥有者的位置分类，调用者决定重试、降级或终止，不能通过字符串匹配恢复控制流。

生产路径不得用 panic 表达可由网络、用户输入、远端状态、磁盘或生命周期竞争触发的失败。仅对不可被外部输入破坏的内部不变量使用断言，并优先让类型系统消除不可能状态。

## 模块边界

Rust crate 用于隔离可复用协议/平台能力，daemon 内部子模块用于隔离同一进程内的状态所有权。不要仅为了缩短文件把紧耦合函数机械搬家；一次有效拆分至少满足下列一项：

- 新模块拥有独立状态和不变量；
- 新模块暴露小而稳定的输入/输出接口；
- 新模块可以在不启动完整 daemon 的情况下测试；
- 新模块把平台依赖、协议编码或副作用与纯决策逻辑分开。

反过来，如果两个模块需要频繁互相读取内部字段、共享锁或循环调用，应重新确定状态所有者，而不是增加更多 facade。

daemon 内存在两类作用域，拆分方式随之不同：

- **真实 `mod` 作用域**（`udp/`、`transport/`、`dplpmtud/`、`network_outbound/`、`relay_runtime/`、`relay/`）使用真正的 Rust 子模块，可以单独编译和测试；
- **`include!` 作用域**（`lib/daemon/`、`lib/direct_runtime/`、`peer/manager/`）沿用「薄父文件 + 子文件」惯例。这些文件与同作用域的其余文件共享一个 crate-root 或 `peer` 模块作用域，因此拆分不需要放宽任何可见性，代价是它们不能作为独立 `mod` 单独编译或测试。

## Daemon 模块归属

DPLPMTUD 的尺寸换算、路径身份、wire 编解码和 reducer 分别位于 `dplpmtud/sizes.rs`、`identity.rs`、`wire.rs`、`state_machine.rs`。`runtime.rs` 负责 worker 生命周期和 budget publication，不再维护第二份 reducer 判定。测试按相同边界分组。

`transport/sessions.rs` 拥有 active、previous 与 pending 会话。加密和解密是这个模块的子模块，共享同一份会话状态；外部接收循环不能直接修改会话字段。接收索引不是唯一身份，同一个 peer 的多个 pending key 匹配索引时，必须逐个验证认证结果，并仅提升通过认证且通过 fencing 的精确 token/session instance。重放错误按 `WireGuardError` 变体分类，不能匹配错误文本。

`network_outbound/queue.rs` 拥有 pending FIFO 和 per-peer 调度，`fast_path.rs` 拥有快路径缓存，`send.rs` 负责加密与 handoff，Direct 和 Relay 发送分开。超过单队列总字节上限的单包直接丢弃，不能先驱逐有效队列再接纳超限包。

`relay_runtime/connection.rs` 保持连接及 renewal 生命周期的单一所有者；`supervisor.rs` 决定重连，`write_boundary.rs` 封装写入许可，validation 与 probe 调度使用独立模块。

UDP 的 `core.rs` 和 `dynamic_punch.rs` 使用真正的 Rust 子模块，而不是文本 include。`UdpTransport` 仍是进程内共享的权威状态，不能为拆分另建平行状态副本。socket registry、business MTU、peer cleanup、Direct validation、diagnostics、learning cache、provisional socket lifecycle、birthday wave 和 punch sender 按职责分组；可变 cache/guard 内部字段留在所属模块。模块划分不代表所有函数复杂度或真实设备风险已消除。

## 源码体积与增长门禁

`scripts/quality/check_code_health.py` 检查 Rust 源码体积：普通生产文件上限为 96 KiB，独立测试文件为 192 KiB，按 LF 规范化字节计算。体积是审查提示，不是圈复杂度、耦合度或正确性的证明；不得靠删注释、压行或移动同一状态的访问点来满足门禁。

历史超限文件在脚本中有明确上限。CI 通过 `P2WLAN_QUALITY_BASE` 指定 PR 基线或 push 前提交，取静态上限与基线文件大小的较小值，因此已缩小的文件不能在后续 PR 中重新增长。离线运行未指定 `--base-ref` 时只检查静态上限；本地完整比较使用：

    python3 scripts/quality/check_code_health.py --base-ref main

当前没有例外：daemon 控制事件、direct_runtime 打洞、peer manager 与两个测试热点都已回落到统一预算。文件回落到统一预算后必须删除例外；缺失文件或过时例外也会让门禁失败。

## 精确测试选择

选定 Rust 场景由 `scripts/quality/run_rust_tests.py` 执行。它从 Cargo 本次构建输出获取测试程序，而不是按文件修改时间猜测二进制；在运行前枚举测试，拒绝零匹配和仅匹配 ignored 的选择，并核对实际执行数量。Hard↔Hard 场景使用 `--each` 保持进程隔离。

默认选择 library target；`--package` 指定 crate，`--bin` 显式选择对应 binary test target。通用套件过滤掉的 Hard↔Hard 测试须在其实际 target 中单独执行，不能由另一个 target 的同名过滤器代替。

    python3 scripts/quality/run_rust_tests.py dplpmtud
    python3 scripts/quality/run_rust_tests.py hard_hard_ --each
    python3 scripts/quality/run_rust_tests.py hard_hard_ --package p2pnet-nat --each
    python3 scripts/quality/run_rust_tests.py hard_hard_ --bin p2wlan-daemon --each
    python3 scripts/quality/run_rust_tests.py transport::tests::pending_receiver_index_collision_tries_every_matching_key --exact

测试模块改名必须同时更新 workflow、验收脚本和 evidence contract 的完整 test ID。失效过滤器不能视作通过，不得删除真实断言或降低测试数量来让流水线变绿。

UDP consent 测试可以在原 transport 上安装仅测试构建可用的时间线：最多记录 32 条带 nonce 和本机单调时间的发送返回、ACK 解码、采用锁、匹配、健康提交及轮次回收观测。记录不等待锁、不唤醒协议任务；容量用尽、锁竞争或损坏均计入 `dropped`。失败输出中的缺失事件不能解释成“该步骤未发生”，成功样本也不能解释为旧失败的根因证明。记录不会更改原断言、时限或健康状态所有者，生产构建不包含该时间线。

CI 的通用 workspace 套件由 `scripts/quality/run_cargo_test.py` 执行一次。Linux 使用 `--all-targets`，Windows 保留包含 doctest 的默认 target 范围；原 `--test-threads=1 --skip hard_hard_` 不变。包装器添加 Cargo JSON 构建输出，记录源码、工具链、原退出状态及有界日志；原测试失败不会因采证成功变为通过，也不会因复制失败被重跑。

    python3 scripts/quality/run_cargo_test.py --all-targets --evidence-dir ../p2wlan-rust-general-evidence

Business MTU Linux 验证也使用该包装器：workspace 步骤显式传入 `--all-features`，保留原 feature 和 target 范围；`--hard-hard-lib` 固定执行 daemon lib 的 `hard_hard_` 子集，在同一个原生测试进程中串行运行，保留共享状态竞争覆盖。该模式拒绝与 `--all-targets` 或 `--all-features` 混用，零执行或仅 ignored 的成功输出不能通过。CI 其他 Hard↔Hard 精确选择器仍使用原来的隔离入口。

Path State Machine 的 Linux workspace 步骤使用包装器的默认 target 范围，包含原 doctest；Hard↔Hard 步骤使用 `--hard-hard-lib`，保留同一进程中的串行共享状态覆盖。任一步骤失败时，CI 上传该次执行的源码、工具链、原退出状态、有界日志和可确定身份的原生失败程序，保留 7 天；采证不触发重跑，成功的采证不会覆盖原测试失败。

证据目录必须是仓库外尚不存在的目录。原生测试失败时，仅从同一次 Cargo 的 compiler-artifact 与最终 Running 记录绑定程序，并校验文件身份、大小与摘要后留存实际字节。构建失败、doctest 未报告可执行文件、身份变化或容量超限时明确记录不可用，不扫描 target 猜测，也不重建旧失败产物。每条输出流最多归档 64 MiB、解析行最多 2 MiB、构建记录最多 512 个，失败程序最多 1 GiB；超限继续排空原 Cargo 输出，并使证据资格失败。通用 CI 与 Business MTU Linux 原生套件失败时上传上述证据；其他工作流和精确选择器需使用各自证据入口。

原 Cargo 退出后，两条输出流合计最多等待 5 秒收尾，避免后代继承管道导致 EOF 永不抵达；这不改变测试运行期限。到期记录 `stream_not_closed_after_cargo_exit`，日志标为不完整，不宣称最终摘要或已绑定的失败程序。泵线程停止接受新数据，残留阻塞读取随包装器进程退出关闭；不等待不归包装器直接所有的后代，也不向它们发送信号。原 Cargo 非零退出码仍保留；原退出为零而采证失败时包装器失败。

## 跨工作流门禁

`scripts/quality/check_required_gates.py` 将验证运行绑定到源码 SHA、所属工作流、触发事件和实际任务。同一查询已观察到的 `push` 或 `pull_request` 运行若从后续完整列表中消失，会在既有 API 重试上限内重新读取列表；若当前列表仍不完整，门禁按原轮询间隔在同一总截止时间内等待新快照，到期仍不一致返回 `api_error`。只保留运行身份用于发现列表回退，先前的成功不能代替当前结果。最初缺失的运行、真实失败、取消和无效响应仍拒绝合并；重读使用原分页上限和命令行总截止时间，不重置期限。

## Android CI 插件仓库

Android APK 的两个 CI 构建任务使用 runner 临时目录中的独立 `GRADLE_USER_HOME`。`scripts/release/prepare_android_gradle_repositories.py` 只接受 Git checkout 外尚未存在的绝对路径，验证 Flutter SDK 后，将仓库内的 init 脚本按原字节安装到私有 `init.d`；已有目录或符号链接会使准备失败。

init 脚本通过 `FLUTTER_ROOT` 精确限定 Flutter SDK 的 Gradle included build，将 `org.jetbrains.kotlin` 组的插件依赖交给 [Google Cloud 的 Maven Central 官方镜像](https://storage-download.googleapis.com/maven-central/index.html)，其他插件仍使用 Plugin Portal。Gradle 的根项目插件仓库不会自动继承到 included build。此配置不改写 SDK、插件版本或 wrapper 校验值；构建失败仍按原任务规则处理。

## 依赖审计输出

Rust 依赖摘要由 `scripts/security/dependency_reports.py` 的 `rust` 子命令生成。工作流分别保留 cargo-deny 的 stdout 与 stderr，并通过 `--root-deny-stderr`、`--fuzz-deny-stderr` 一起提交诊断；有效的 stdout-only JSON 输出也可使用。摘要分别记录两条输出流的记录数量及 advisories、bans、licenses、sources 完成计数，不推断跨流时间顺序。

每套依赖图必须有且只有一份覆盖上述四项的完成总结。输出为空、无法解析、记录结构不完整、含错误诊断或总结报告错误时，即使工具退出状态为零也不能通过。重复版本等警告仍按 `deny.toml` 原策略分类，不添加豁免。每套图两条流合计最多读取 16 MiB 和 65,536 条非空记录，单条 JSON 的容器嵌套最多 256 层；字符串中的括号不计入嵌套。超限使证据失败，不把截断内容当作完整扫描结果。

## 变更审查

涉及连接、并发或数据面的 PR 至少回答：

- 哪个组件拥有被修改的状态；
- 使用了哪些 generation、revision、incarnation、owner token 或 session identity 进行 fencing；
- 是否新增队列、锁、后台任务、重试或缓存，它们的上界和取消条件是什么；
- 失败发生在 handoff 前、handoff 后还是状态未知阶段；
- Direct 与 Relay 是否可能对同一密文产生重复交付；
- 是否改变 MTU、replay、rekey、room authorization 或路径选择不变量；
- 哪些测试证明正常路径、超时、取消、重复、过期和并发竞争。

纯重构应尽量保持行为测试不变。行为变更应先说明不变量，再更新实现和测试，避免用大规模重命名掩盖协议变化。

## 测试分层

- 纯函数和状态机转移使用快速单元测试；
- crate/模块边界使用集成测试验证契约；
- daemon 使用确定性的 lifecycle、rekey、route、room、Direct/Relay 与 NAT 场景测试；
- 真实 TUN、Windows lifecycle、移动端和公网 NAT 属于平台/环境验收，不能由 mock 测试宣称替代；
- 发布包验证必须继续绑定源码 commit、嵌入版本和产物摘要。

测试应优先验证稳定不变量和结果，不依赖 sleep 猜测调度时机。需要时间推进时优先使用显式 deadline、可注入时钟或事件同步。

## 可观测性

日志用于解释事件，metrics/status 用于机器判定。高频数据面不得为每个正常包输出 info/warn；正常热路径仅保留采样或 debug/trace 诊断。状态变化日志应包含稳定 reason code 和必要 identity，但不能记录密钥、token、完整凭据或可还原业务载荷。

Linux 原系统 TUN 验收的 `scripts/parallel-rooms/linux_tun_evidence.py --write-facts --kernel-read-facts` 使用原父进程拥有的两个 daemon 控制连接，按启动后的原 probe 计划追加预期输入。每个 daemon 最多登记 1000 个请求，作用域最多 120 秒，两条控制流各最多收发 4 MiB；注册只能追加，不能替换或重新计时。父进程在原 daemon 首次 poll/wait 前绑定原 Popen 出生身份与 Unix peer credentials；daemon 只读取自身 Linux 出生身份、网络 namespace、boot ID 与 CLOCK_MONOTONIC。具体系统设备完成真实 read 后才创建私有来源，注册 JSON、Any 与 Mock 输入不能创建该来源。

读取记录保留完整 128 位 run/round/request nonce。TCP 以原 SYN 序号和有界字节覆盖处理分段、合并与重传；每包最多关联八帧，冲突使该流不具备完整覆盖。父进程将实际读取与原子进程写入流、原请求截止时间分别比较，保留原 normal32/fault32/stall16、未发送 TCP 与晚到回程。读取覆盖字段只描述历史字节；`native_credit` 另外记录唯一 PeerManager 对原 KernelRead、加密和实际 UDP/Relay Full、认证入站与同设备完整写入的最终事务。该事务在原期限内核验当前 session、generation、生命周期、路径和原房间许可后消费一次确认，记录 `commit_monotonic_ns`。历史确认不代表快照读取时连接仍然可用；新请求须重新核验当前所有者。采集结束只关闭实际拥有的连接，进程清理后不再查询 PID 或补取控制记录。

原读取的身份期望仍执行一次原 epoch try。实际发送持有同一 epoch，在原epoch与连接写锁同时取得时、generation检查和调用方诊断之前发布仅含 peer、VIP、generation 与生命周期的不可变期望；每个 PeerManager 最多一个弱引用槽，且只在真实采集作用域有效时准备。读取须在原 try 前观察到该期望，并在原观察时间确认其仍有效，才可用于 epoch 竞争时的首次身份记录。该期望由持有实际 epoch 的准备作用域拥有；路径选择仅改变路径、候选提名和诊断，后续预算与原输入检查只读这些身份。期望覆盖同一epoch下不改变这些身份的准备操作，包括物理元数据与DirectFirst路径完成；退出准备、取消或实际解锁前立即失效；过期、停止、所有者不符及其他锁竞争保留原拒绝。已缓存的首次失败不能事后补填。该期望不创建 KernelRead、Full、SystemTun 或发送许可，后续身份与最终 owner/once 事务仍使用实际权威锁。

只读身份期望的元数据可在取得实际 peer Emit 锁之前准备，由同一有界发送 Future 持有。实际本地端点查询继续持有原 Emit，真实加密输出缓冲区在查询之后分配；等待 Emit 期间保持原来的明文缓冲区数量与容量记账，取消或原期限到达即释放。所有 session、计数器及物理交付仍由同一实际 Emit 锁保护。认证端点学习的公共入口通过同一个 epoch/连接写锁获取器排队，等待连接写锁期间释放 epoch，取得两把实际锁后再使用当前 generation 修改候选；已持有 epoch 的 UDP 入口继续使用原有事务。

登记表在采集作用域暴露前预触原有空闲 flow 容量和生产者键存储，实际长度与生产者集合仍为空。临时标签在暴露前清除，不构造来源、登记回执或 IO 事实。原输入互斥锁仍是唯一追加权威；实际原读和认证输入继续执行原来的单次 try，竞争仍拒绝。登记的容量、冲突、修订和发布检查顺序不变。

控制连接的注册和快照请求携带发送方原有的一秒交换截止时间；原写入窗口沿用原 OS 请求截止时间。单个控制任务可在这些既有期限内让出调度、等待元数据短临界区，最多一个等待者；取消释放等待位置，锁中毒与过期仍拒绝。数据包观察和最终网络 owner 核验保持 try-only，元数据等待不重发业务、不续期，也不清除原来源缺失。快照只序列化已有结果。

`native_credit.owner_check` 记录原最终事务最后到达的检查位置，区分发送锁登记表、发送锁、Direct 提交编号、端点、来源及预算发布等位置。该固定诊断码只解释已有终态，不授予 owner 或发送信用；缺少位置不推导通过，失败终态不因后续快照而重新确认。

Linux TUN 验收失败时，归档保存与原报告镜像 SHA 一致的既有 daemon/control 字节及清单。每个镜像最多 1 GiB，共两个镜像；缺少原报告哈希或已有镜像时记录不可用。镜像留存发生在测量流程结束后，不改变原请求、进程组与回收记录。

新增关键状态机时，同时考虑：当前状态、最后一次转移原因、失败计数、队列/任务规模和版本 identity 是否能从现有诊断入口获得。可观测性不是在出现事故后再补日志。

NAT 仿真的 `NAT_SIM_PROCESS_BIRTH=1` 可选开启原生进程出生身份记录；默认关闭。`launch_identity.py exec --process-birth` 在同一进程原始 exec 前读取自己的 Darwin 原生身份，以私有、最多 4 KiB 的 `.birth` sidecar 绑定原启动记录摘要、源码、角色和产物摘要，不读取 token stdin。原 schema 1 启动记录与严格收集器保持不变。其他平台或原生查询失败会保留不可用原因，诊断写入失败不能阻止原 exec。该记录只为后续受归属约束的观察提供出生身份 fence，不能证明 exec 成功、当前 PID 仍对应原实例或 TCP 已建立；原 exec 失败会使该绑定不可用，禁止按晚到的 PID 查询补造原实例身份。固定四例策略测量会将显式 opt-in 纳入各例原环境，保持原预算与分母。

Darwin 上同时设置 `NAT_SIM_PROCESS_BIRTH=1 NAT_SIM_TCP_OBSERVER=1` 可诊断每轮第一个原始并发 a/b status 请求。构建阶段保留原生观察程序、源码与产物摘要；固定四例复用同一份程序。原 Bash 仅为已经登记的两个 daemon 启动观察器，并在原 PIDS 清单登记观察器及原 HTTP 子进程。采样 Python 只观察自己拥有的实际 curl；在 poll/wait 前读取其出生身份，后续每次 TCP 查询都验证原出生身份、UID 和直接所有者，并在 FD 读取后再次复核所有者与目标。

准备及预热消耗原固定工作期限；原生 ready 等待最多 5 秒，TCP 查询最多 200ms，原生 watchdog 为 10 秒、最多 7 条非退出命令、128 个 FD。两侧观察器共用最多 1 秒的 join 界限，并受原工作期限收紧，不提前启动或延长轮次 finalizer 的资源宽限；未回收者仍归原 PIDS 清理。私有 FIFO 的读端与原生写端独立打开，不共享非阻塞标志。客户端保留 0/25/75/125/175ms 五个预定采样点及其实际时间；错过窗口、进程退出、身份不匹配、容量超限或取消都不能证明“没有 socket”。只保留 IPv4 TCP 与目标端口匹配的顺序 FD 行，不声称全局原子快照。原 curl 参数、认证 stdin、连接/请求/wrapper 时限、HTTP 验收和轮次分母保持原规则；诊断不能把原 HTTP 失败改为成功，也不能据此给出策略收益或旧失败根因。原始记录位于私有轮次的 `tcp-observation/`，取消和强制清理必须结合原所有者退出记录解读。

原生 overlay 验证的 `p2pnet_daemon::overlay_native_credit=debug` target 将 REQUEST/ACK 拒绝的 nonce、seq、类型化结果与原 Full publication 的实际观察点关联。ACK 字段只在原 owner/once 事务返回后采样；publication 日志只在原观察时间已写入后输出。缺失时间保留为空，这些顺序快照不构成原子事实，也不能把晚到的 publication 用作较早原读的信用。该 target 不记录密钥或载荷，不改变原读时间、成功计数、拒绝规则、重试或时限。NAT 仿真的默认诊断过滤器包含该 target；自定义过滤器需自行保留它。

## 完成标准

代码完成不等于功能能运行一次。一个改动只有在以下条件满足后才可合并：边界清楚、资源有界、错误可分类、取消路径完整、核心不变量有自动测试、CI 通过、文档只描述已实现行为，并明确真实设备或公网环境仍未验证的部分。

原控制写窗口的预期输入可从现有只读发布单元查询；该查询只携带注册时的 producer 标签和同一计划 Arc，不产生原生读取、Full、SystemTun 或当前 owner 事实。命令仍在原期限内取得真实登记锁，重新遍历唯一 producer、检查原形状及同一 Arc，再按原顺序检查跨窗口冲突、当前时钟和重复写入后安装元数据。

Linux TUN 失败采证只保留原报告摘要绑定的实际程序，不重建或执行。普通、Relay 和房间撤销范围共用 `linux-tun-original-images`，按 daemon/control/relay 最多保存三个镜像，每个上限 1 GiB；各范围保留独立 manifest。共用目录绑定相同 checkout、run ID 和 attempt，已有镜像必须与当前原程序和报告摘要一致。schema 2 的 `images[].archive_member` 指向归档内共用成员；未启用 `--image-store` 时仍输出 schema 1 的范围内镜像。缺少原程序或摘要、身份变化、冲突、符号链接与容量超限均不能获得采证资格。

Relay控制包继续使用原counter emit锁保护加密和实际writer结果。单次控制尝试可冻结一份Relay发送诊断和最多4KiB错误摘要，在该锁释放后输出并记录原advisory尝试；取消只输出实际已提交的诊断，不生成发送成功或当前owner事实。两个Relay writer仍在真实write_all和原Full观察之后通知原completion，再调用同步诊断，避免订阅回调阻止已经完成的结果被调用方接收。原队列、writer边界、超时、错误分类和物理观察来源保持。
