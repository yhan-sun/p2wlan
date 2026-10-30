# CLI 参考

| 命令 | 作用 |
| --- | --- |
| p2wlan config set control URL | 设置 Control 地址 |
| p2wlan config show | 查看非秘密配置 |
| p2wlan login -u USER | 登录或注册当前账号 |
| p2wlan account show | 显示当前账号身份 |
| p2wlan up / down | 启动或停止虚拟网络 |
| p2wlan status [--json] | 查看 daemon、设备和路径状态 |
| p2wlan status --resources | 读取显式启用的软件缓冲观测 JSON；与 --json 互斥 |
| p2wlan config set resource-capture true / false | 设置下一次 daemon 启动的软件缓冲观测开关，缺省关闭 |
| p2wlan doctor | 输出结构化诊断摘要 |
| p2wlan room list | 列出房间 |
| p2wlan room connect ID | 连接房间 |
| p2wlan room disconnect ID | 断开房间 |
| p2wlan route verify / repair | 检查或修复本机路由 |
| p2wlan logs -f | 跟随 daemon 日志 |
| p2wlan support-bundle | 生成本地支持包 |
| p2wlan support-bundle --upload | 经用户确认后上传支持包 |
| p2wlan update | 按当前安装源更新 |

准确参数以 p2wlan help 和当前 Release 内的 CLI 为准。登录、配置和查询不要使用 sudo；创建 TUN、路由和 systemd 服务可能需要权限。

## 本地节点诊断

认证后的 `GET /status/peer/<node_id>` 返回当前节点快照。连接表短暂争用时执行有界读取；持续争用返回 HTTP 503 与 `peer_snapshot_busy`，不使用旧缓存代替当前快照。只有实际读取连接表并确认节点不存在时才返回 HTTP 404。完整快照仍受原请求超时限制，连接取消会结束对应读取。

## OS UDP/TCP 请求计划

`python3 scripts/dual-end/probe_request_plan.py prepare --help` 提供请求计划生成入口。`--transport udp` 或 `tcp` 选择工具，地址、端口、run/round nonce 及时间配置须与后续 probe 一致；`--capture-id` 与 `--producer-scope` 均为 32 位小写十六进制关联 ID。`--output` 必须是 Git 检出外的新绝对路径，POSIX 文件权限为 0600。准备计划只生成输入文件，不打开 socket。

随后为 `udp_business_probe.py probe` 或 `tcp_business_probe.py probe` 添加 `--request-plan /absolute/new-plan.json`。需同时分发 `probe_request_plan.py`、`udp_business_probe.py` 和对应 TCP 工具；计划核对工具指纹、完整请求 nonce、流、数量及时间配置，不匹配时在打开 socket 前失败。未提供计划时仍使用随机请求 nonce，旧的双文件分发方式保持可用。

默认仍是 8 个请求、100ms 间隔、1000ms 单请求超时、10000ms 总期限及 128 字节负载。计划加载发生在原测量时钟之前，不延长期限或重发请求；TCP 保持一次连接。报告中的 `prepared_probe_input_only` 仅表明使用了计划输入，`daemon_registration_verified` 保持 false，不能据此确认真实 TUN、Direct 或当前连接归属。

两个 probe 的可选 `--write-facts-fd N` 将原 socket 写入观察送入调用方提供的 POSIX 管道，必须同时使用精确请求计划。调用方先创建管道、把写端设为非阻塞并显式传入子进程；工具验证写端后复制私有描述符，仅关闭自己的副本，不设置调用方的文件标志。需额外分发 `probe_write_facts.py` 和 `probe_process_identity.py`。Windows 不支持这个选项；不传选项时保持原有运行方式。

管道中的 JSONL 按序记录计划/工具指纹、当前生产进程、原始单调时钟起点、socket 身份，以及每次原 `sendto` 或 `send` 的时间、帧摘要、偏移、请求字节数、实际返回字节数或数字 errno。TCP 每次分段写入沿用同一原请求截止时间。每条记录最多 512 字节，只尝试一次原子非阻塞写入，总计最多 8192 条、4 MiB；没有采证队列、重试或后台线程。采证耗时计入原预算。管道满、关闭或容量耗尽时停止发出记录，报告保留 `emission_gap_reason`，业务请求仍使用原数量、次数及期限。

这些记录仅属 `original_os_socket_write_observations_only`。Linux 可记录本进程出生时间、boot 和命名空间；其他 POSIX 平台明确标记 Linux 出生/同 boot 时钟不可用。接收方仍须核对自己创建的生产进程和管道、原计划与源码、完整序号及结束记录，再接真实 TUN、物理发送、房间许可与当前连接所有者。`daemon_registration_verified` 和 `kernel_tun_verified` 均为 false，管道接受记录不能证明这些条件。

## Linux TUN 原有子进程写入采集

`python3 scripts/parallel-rooms/linux_tun_evidence.py --help` 提供 Linux 同机 TUN 验证入口。显式添加 `--write-facts` 后，正常、`--fault-recovery` 和 `--server-stall` 三种模式分别保留原 32、32、16 个计划请求，同时为每个原 probe 准备完整请求计划和非阻塞管道；默认不开启采集。仅原 probe 子进程继承写端，进程组 anchor 不继承；父进程在原 `Popen` 返回后关闭自己的写端，并在回收子进程前绑定原出生身份和目标命名空间。

同一时间最多采集一个 probe，父进程和子进程各最多持有两个管道描述符。每次原轮询只读取最多 4096 字节，原始记录缓冲每个 probe 最多 4 MiB；流、计划、原报告和原身份不一致时保留缺口。原有进程组/句柄上限、探测次数及绝对期限保持，采集成本消耗原期限。退出或取消后先关闭采集描述符、按原规则回收资源，再保存未完成的原始记录；不根据接收到的 PID 查询或重建身份。

每个 probe 的计划、JSONL 和采集结果保存在原输出目录，权限为 0600；结果保留从原 `Popen` 捕获的身份快照，后续读取不重新查询该 PID。主报告的 `passed` 保持原业务验收含义，`original_write_observations.passed` 单独表示全流及 Linux 原出生/同 boot 时钟核对结果；显式启用时，命令仅在两者均通过时返回零。采集失败不补发请求、不重试连接，也不改变原业务结果和失败分母。该结果仍是原 OS 写入观察，daemon 注册、真实 TUN 读归属、物理发送和最终连接 owner 的验证标志均为 false。
