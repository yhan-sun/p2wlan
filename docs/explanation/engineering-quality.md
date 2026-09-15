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

## 当前复杂度棘轮

`scripts/quality/check_code_health.py` 是可执行复杂度策略。普通 Rust 生产模块不得超过共享预算；当前已经超出预算的历史热点采用“只降不升”的字节上限。它们不是允许永久保留的大文件，而是待拆分债务：

- `client/daemon/src/transport.rs`：拆出 session registry / responder lifecycle、validation framing、inbound decrypt/evidence、outbound encryption/order gate；
- `client/daemon/src/dplpmtud.rs`：拆出 wire format、path identity、budget publication、runtime state machine，并把大体量测试迁到独立测试模块；
- `client/daemon/src/network_outbound.rs`：拆出 per-peer queue actor、Direct sender、Relay sender、fast-path cache 与 accounting；
- `client/daemon/src/relay_runtime.rs`：拆出 connection lifecycle、peer stream/session、backpressure 与 reconnect policy。

拆分必须保持原有类型语义和测试，不以“先移动再修”为理由同时改变协议行为。每次拆分后应降低对应 ratchet ceiling，直到该条目可以从 legacy 列表删除。

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

新增关键状态机时，同时考虑：当前状态、最后一次转移原因、失败计数、队列/任务规模和版本 identity 是否能从现有诊断入口获得。可观测性不是在出现事故后再补日志。

## 完成标准

代码完成不等于功能能运行一次。一个改动只有在以下条件满足后才可合并：边界清楚、资源有界、错误可分类、取消路径完整、核心不变量有自动测试、CI 通过、文档只描述已实现行为，并明确真实设备或公网环境仍未验证的部分。
