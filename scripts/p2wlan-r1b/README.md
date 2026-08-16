# R1b 前置生死探测 — 生产 STUN CHANGE-REQUEST 能力

> 结论（2026-08-17）：**三台生产 STUN 均不 honor RFC 5780 CHANGE-REQUEST →
> live-safe active filtering 探测在现实配置下拿不到 EIM/AD 信号 → R1b（让 `f=` 独立
> 于 `m=` 变准）无增量收益，BLOCKED。不硬做（写出来是永远走 fallback 的死代码）。**

本目录是 R1b 的**前置探测工具**（可复跑），而非 R1b 本体。R1b 本体（live-safe
CHANGE-REQUEST 探测接稳态 gather）在 `scripts/punch-research/MIGRATION_RFC.md` 标注为
BLOCKED，解锁条件见末尾。

## 三脚本

| 脚本 | 用途 |
|---|---|
| `stun_change_request_probe.py` | 基础单次探测：每 STUN 发 baseline / change-ip+port / change-port 三请求，判定 SAME / CHANGED / NO_RESP。 |
| `stun_change_request_probe2.py` | 多迭代（默认 6 次）、NAT 混淆感知版；**change-port 为主判据**。 |
| `stun_probe_selftest.py` | loopback mock：证明「探测能检测正例」。若它对本地 mock 打出 CHANGED、而对生产打出 SAME，则生产确不支持（探测未坏）。 |

用法：

```bash
python3 scripts/p2wlan-r1b/stun_change_request_probe2.py          # 多迭代能力探测
python3 scripts/p2wlan-r1b/stun_probe_selftest.py                 # 正例检测自证（需 loopback UDP 正常的环境）
```

STUN 列表硬编码在脚本内（`stun.cloudflare.com:3478` / `stun.miwifi.com:3478` /
`stun.l.google.com:19302`，与 `client/daemon/src/lib.rs` 默认一致）——无真实基础设施 IP。

## §4 实测表（2026-08-17，3 STUN × 6 迭代 = 18 样本）

| STUN | 解析地址 | baseline（可达性） | change-port（主判据） | change-ip+port |
|---|---|---|---|---|
| stun.cloudflare.com:3478 | 162.159.207.0 | SAME×6 | **SAME×6 → 确凿忽略** | NO_RESP×6 |
| stun.miwifi.com:3478 | 111.206.174.2 | SAME×6 | NO_RESP×6 → 无信号 | NO_RESP |
| stun.l.google.com:19302 | 74.125.250.129 | SAME×6 | **SAME×5 + NO_RESP×1 → 确凿忽略** | NO_RESP |

**18 次迭代，changed-source 响应出现次数 = 0。**

## 判定逻辑（为什么「不支持」是确凿的，不是假阴性）

- **主判据是 change-port，不是 change-ip+port。** change-ip 会让服务器从不同
  external IP 回包，该响应几乎必然被本机 NAT 黑洞（本项目记忆中的 CGNAT UDP
  黑洞），`NO_RESP` 在此毫无诊断力。change-port 保持同一 external IP，响应能穿 NAT
  回来——所以 change-port 的 **SAME 是确凿的「服务器把 CHANGE-REQUEST 当普通请求从
  原址回了」**。
- **更深一层：在不支持 CHANGE-REQUEST 的 STUN 上，RFC 5780 filtering 测试逻辑本身就
  无效。** filtering 判定靠「changed-source 响应收不到」推断 APDF；但服务器忽略 change
  时，「收不到 changed 响应」是歧义的——分不清「我的 NAT 过滤(APDF)」还是「服务器压根没
  发 changed 响应」。无信号可判 → 探测无料可喂。
- cloudflare 与 google 在 change-port 下拿到 SAME，miwifi 拿不到 changed-source。
  外网收发路径本身通（baseline 全 SAME），所以 SAME 不是「脚本收不到包」，而是「服务器
  确实没理会 change」。

## Sandbox 局限（诚实声明）

本 sandbox loopback UDP 坏（最小 ping/pong 都 timeout），故 `selftest.py` 的**正例
检测能力**未当场证明。这是本探测唯一未闭环的一环。但否定结论不依赖正例自证：
「生产 STUN 不配合」由 18 样本的 SAME / NO_RESP 证据链独立支撑。

## 附带发现（非 R1b 范围，供日后排查）

`stun.miwifi.com:3478` 连 change-port 都 NO_RESP，而 baseline SAME 可达——这台国内
STUN 对**带 CHANGE-REQUEST 属性的请求**行为异常（可能对含该 attr 的请求限速/丢弃）。
任何未来想复用 CHANGE-REQUEST 的功能（不止 R1b）都会踩到它，值得单独排查。

## R1b 状态与解锁条件

- **状态**：BLOCKED。active filtering 探测在现有第三方公共 STUN 上无增量收益。
- **正确的长期方向**（非现在做）：本项目全自托管——**一台自托管、honor
  CHANGE-REQUEST 的 STUN** 能彻底绕开「第三方服务器忽略 change」问题。届时重跑
  `stun_change_request_probe2.py` 指向自托管 STUN，`selftest.py` 先证正例可检测，
  再启动 R1b 本体。
- **降级备选（未采用）**：对 `m==EIM` 无差别开散射可修 EIM+APDF 漏散射，但 over-scan
  所有 EIM（含 full-cone）、且要动 R1 冻结的 `scatter_decision`，钝刀治非主场景，不值。
