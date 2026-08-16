# LIVE_PROTOCOL.md — Gate2 真实网络运行协议

> Gate2 仅在 Gate1（TEST_REPORT_P2.md 自检清单）全部通过后执行。
> 目标：验证模拟结论在真实 NAT/网络下的可达性，对照达标线：
> **成功率 ≥95%**（≥20 轮）、**P50 建立 ≤1.5s**。

## 1. 前置条件

- 两台真实主机（A / B），公网可达；双方出网经真实 NAT（目标覆盖：
  cone、symmetric、CGNAT、运营商级 NAT 均记录实际指纹）。
- 真实 STUN 服务器列表（推荐自建或 `stun.l.google.com:19302` 等多服务器；
  若需 filtering/hairpin 探测，服务器须支持 CHANGE-REQUEST——RFC 5780。
  不支持时 puncher 自动降级：filtering=unknown、hairpin=unknown，不判失败）。
- 信号端口（默认 9900）在防火墙放行；UDP 出站放行。

## 2. 运行步骤

1. 监听端（A）：
   ```
   scripts/punch-research/live_run.sh listen 9900 stun.l.google.com:19302 \
       --hold-s 10 --session-out /tmp/live_a.json | tee /tmp/live_a.log
   ```
2. 连接端（B）：等待 A 就绪（日志出现 `[A] NAT profile: ...`）后：
   ```
   scripts/punch-research/live_run.sh connect <A_IP> 9900 stun.l.google.com:19302 \
       --hold-s 10 --session-out /tmp/live_b.json | tee /tmp/live_b.log
   ```
3. 采集：P2P ESTABLISHED 后保持 hold 秒数验证 keepalive；无 P2P 时 window 窗口结束自动退出。
4. 多轮：重复步骤 1-3（≥20 轮，每轮更换 seed/端口或自然间隔 ≥30s 消除 NAT 表残留）。

## 3. 判定流程

```
python3 scripts/punch-research/live_analyze.py --dir /tmp/live/ --timeline
```

- 单轮判定：`result=p2p`（双方），`establish_ms` 计入 P50。
- 达标线：成功率 ≥95%（成功轮 / 总轮）；P50 ≤1.5s。
- 指纹记录：mapping/allocation/filtering(allow|deny|no-response)/hairpin(supported|unknown)
  —— 用于与真实 NAT 行为对照（检测正确性人工确认：NAT 管理员已知行为 or
  RouterOS/OpenWrt 文档比对）。
- 失败轮分析：检查 `events` 时间线（nat_detect → strategy_selected → probe_sent →
  punch_hit/p2p_established）；未命中时查看 budget_split（哪层耗尽）与 step 学习轨迹。

## 4. 已知边界（结果解释）

- 信号直连信令：puncher 的 `--host/--port` 为 TCP/UDP 直连握手，非生产信令通道；
  真实部署将信号接入 p2wlan signaling（见 MIGRATION_RFC.md R4）。
- 单 socket 检测框架：EI NAT 下 allocation 依赖信令提示（`a=linear`）与打洞期在线学习。
- hairpin 探测真实 NAT 支持度低（多数丢弃）；`unknown` 不判失败，回落中继。
- 运营商 CGNAT（对称/随机分配）预期成功率低于达标线 → 记录为环境特征，
  不视为引擎缺陷（预算/散射已按最坏情形配置）。

## 5. 结果产出

- `/tmp/live/session_{a,b}_<n>.json` + live_analyze 汇总表
- Gate2 结论写入 TEST_REPORT_P2.md 追加节（真实网络对照 + 达标线结果）。