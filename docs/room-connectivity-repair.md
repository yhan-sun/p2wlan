# 房间显示直连但 ping 不通：修复与验收

基线：`d100ea89f3cd4aa5ec75105220dcc419ff9b8bfc`。代码修复不等于现有安装包已更新；本文件不宣称已通过故障用户双端实机验收。

## 修复边界

Windows 旧实现为所有网络共用一个 ICMP 规则显示名，仅在首次创建时设置网段。后续房间只启用原规则，无法放行新房间的入站 echo request。新规则以网卡和网段生成稳定独立 Name，每次校正地址、网卡、协议和启用状态，仅放行该房间网段的 ICMPv4 echo request。保留旧共享规则及管理员策略，不关闭防火墙，不允许任意来源。显式阻断规则或企业策略仍可能禁止 ICMP；执行失败记录 `overlay_icmp_firewall_failed`。

房间出站只允许本机已发现的非 overlay IPv4 源地址安全归一化后再授权。其他设备、个人网络 `10.20.0.0/16`、任意房间 `10.21.0.0/16` 的错误源地址仍拒绝；入站源地址校验不放宽。归一化失败、分片、无授权、过期租约和未知路由都不能绕过授权。绑定特定 IP 的应用仍可能需要修正系统选路，源地址归一化不是通用 NAT。

远端改址撤销旧会话、候选和映射；旧设备删除不能移除已被另一设备接管的 IP。控制面重新注册若改变本房间本机 IP、CIDR 或节点身份，旧实例失效退出，必须重新连接以创建正确 TUN，不能继续展示旧实例为可用。

界面匹配房间设备必须同时满足设备身份（roster 的 `id` 或 `node_id`）和 IP，不能借用被重分配地址上另一设备的直连状态。“链路已建立”仅代表加密传输验证；房间数据另外显示授权状态、近期收包和明确丢包原因，不再称直连加中继数量为“可互通”。

## 诊断字段

`/status.room_dataplane` 与传输状态分离，包含 `authorization_state`、`lease_remaining_ms`、固定原因计数 `drops`、一条有界 `last_drop`、当前授权成员的 `peers`。

`tx_queued_packets` 表示进入本机出站队列，不代表已写 socket 或对端已收到。`rx_delivered_packets` 表示数据已写入本机 TUN，不代表操作系统已回复 ICMP，也不代表对端收到回复。普通 bytes 计数为尽力采样，不能仅靠不增长断定丢包层级。近期收包与 Direct 验证都不等于完整 ping 往返证据。

租约仍最多 30 秒，控制面不可用时保持到期拒绝。正常同一授权续期保留计数；授权成员或 IP 改变清除旧成员流量证据。界面收到快照后使用单调计时校验剩余租约，旧 daemon 不提供该字段时显示未验证。

## 自动化回归

- `cargo test --locked -p p2wlan-daemon --lib room_ -- --test-threads=1`
- `cargo test --locked -p p2wlan-daemon --lib firewall_contract_tests -- --test-threads=1`
- `flutter test test/room_connectivity_test.dart test/room_dataplane_test.dart test/rooms_page_test.dart`（`apps/flutter_client`）
- `scripts/room-connectivity/windows-firewall.ps1`：管理员 Windows、生产 PowerShell 模板；独立规则、精确范围、已有规则修正、幂等和不修改旧规则；仅清理测试自己创建的规则。
- 保留原 Rust/Go/Flutter、Windows 生命周期及 Linux 多房间真实 TUN/netns 门禁，不以新增定向测试替代。

## 发布包双端验收

在实际两台设备上安装包含修复提交的新包，记录双方版本、daemon SHA、房间 ID、设备 ID、IP、TUN/路由与防火墙过滤器。个人网络和至少两个房间同时在线，逐一双向普通 ping，再测试已有监听端口的 TCP/UDP。覆盖离开重入、改 IP、删除旧设备后地址重分配、授权失效和恢复；核对其他房间/个人网络之间仍不可越权互访。

Windows IPv4 的源地址选择应检查实际路由/抓包，不把 `ping -S IPv4` 当作通用验收方法；Microsoft 文档中的 `/S` 参数适用于 IPv6。不要把内部加密探测 ACK 当成 ICMP echo reply。
