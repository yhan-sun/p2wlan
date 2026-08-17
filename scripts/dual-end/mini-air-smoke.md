# `mini-air-smoke.sh`

## 用途

在真实 Mini 和 Air 两台电脑上运行当前 daemon，验证真实 control、relay、UDP Direct 和 TUN overlay。它是本仓库的真实双机主入口，不是 NAT-sim，也不使用 mock TUN 作为 strict acceptance 证据。

验证内容包括：

- 两端使用同一 control URL 和 network/tenant，但使用独立 device identity；
- relay transport 和 peer ACK 就绪后才注入真实业务；
- 双端加密 Direct validation ACK、generation、peer 和 endpoint 一致；
- Direct promotion 后的真实 overlay ping/业务回包；
- 每轮 daemon、设备和 TUN 状态清理；
- 每轮日志、status、poll、audit、路由和指标保存。

## 授权与安全门

真实远端动作必须同时设置：

```bash
ALLOW_STAGING_TEST=1
ALLOW_REMOTE_RESTART=1
```

真实 TUN 需要：

```bash
REAL_TUN=1
PRIVILEGED_SUPERVISOR=1
PERSIST_PRIVILEGED_SUPERVISOR=1
```

第一次运行时 Mini 和 Air 各需要一次系统授权弹窗。之后同一持久 supervisor 会复用授权完成本次多轮启动、停止、TUN 创建和清理；不会把密码写入 shell、日志或 artifact。

## 常用模式

| 模式 | 阶段 | 默认轮数 | 用途 |
|---|---|---:|---|
| `compat` | `compat-baseline` | 3 | 用旧 daemon 建立历史基线，需要 `DAEMON_BIN_OVERRIDE` |
| `strict` | `preflight` | 3 | 当前树 strict Direct 预检 |
| `strict` | `acceptance` | 10 | 当前树真实 Direct 验收 |
| `availability` | `preflight` | 3 | relay-first 首个真实业务预检 |
| `availability` | `acceptance` | 10 | relay-first 首可用和后台 Direct 诊断 |

`strict` 的 Direct SLO 由 `DIRECT_SUCCESS_TARGET_MS` 决定；要验证 3 秒目标必须显式设置为 `3000`。不能使用 `10000` 的结果宣称满足 3 秒 SLO。

## 运行示例

下面示例不包含任何 secret。将尖括号变量替换成实际 staging 参数：

```bash
cd <repo-root>

RUN_ID="dual-real-$(date +%Y%m%d-%H%M%S)"
ARTIFACT_ROOT="$PWD/target/acceptance-artifacts/$RUN_ID"
AB_SEQUENCE_DIR="$PWD/target/acceptance-sequences/$RUN_ID"
mkdir -p "$ARTIFACT_ROOT" "$AB_SEQUENCE_DIR"

env \
  ALLOW_STAGING_TEST=1 \
  ALLOW_REMOTE_RESTART=1 \
  AIR_HOST="<air-management-host>" \
  AIR_USER="<air-user>" \
  AIR_SSH_PORT=22 \
  AIR_SSH_KEY="<absolute-key-path>" \
  AIR_KNOWN_HOSTS_FILE="$HOME/.ssh/known_hosts" \
  REMOTE_CONTROL_URL="https://<control-host>" \
  NETWORK_ID="<dedicated-network>" \
  REAL_TUN=1 \
  ACCEPTANCE_MODE=strict \
  STRICT_PHASE=acceptance \
  ROUNDS=10 \
  DIRECT_TIMEOUT_S=45 \
  DIRECT_SUCCESS_TARGET_MS=3000 \
  PRIVILEGED_SUPERVISOR=1 \
  PERSIST_PRIVILEGED_SUPERVISOR=1 \
  RUN_ID="$RUN_ID" \
  ARTIFACT_ROOT="$ARTIFACT_ROOT" \
  AB_SEQUENCE_DIR="$AB_SEQUENCE_DIR" \
  scripts/dual-end/mini-air-smoke.sh \
  2>&1 | tee "$ARTIFACT_ROOT-terminal.log"
```

当前只能使用 legacy HTTP/TCP relay 时，必须额外显式设置
`ALLOW_LEGACY_PLAINTEXT_RELAY=1`，并把结果标记为非安全诊断；生产或 release 验收必须使用 HTTPS control 和 `tls://` relay catalog。

## 结果判定

### strict

每轮 `round-metrics.tsv` 至少检查：

- `a_direct=1`、`b_direct=1`；
- 两端 validation session/request/ACK/promoted 完整；
- `a_strict_validation=1`、`b_strict_validation=1`；
- `a_matched_acks=2`、`b_matched_acks=2`；
- 双向真实 overlay 回包完整；
- `a_post_direct_traversal=0`、`b_post_direct_traversal=0`；
- `a_non_target_traversal=0`、`b_non_target_traversal=0`；
- `strict_convergence_ms <= DIRECT_SUCCESS_TARGET_MS`。

`strict_convergence_ms` 是两端都完成 Direct promotion 的配对耗时，不是 ping RTT。
`validation_rtt_ms` 是加密 Direct validation ACK RTT；真实业务延迟应另外看 overlay ping/业务 echo。

### availability

必须确认首个真实业务回包来自 relay ingress。TCP connect、writer queue、relay metrics 或本地 probe ACK 都不能单独作为 relay 可用证据。重点字段是：

- `first_usable_after_relay_ms`；
- `first_usable_path_a/b`；
- `a_relay_peer_confirmed/b_relay_peer_confirmed`；
- `a_overlay_round_trips/b_overlay_round_trips`；
- `failure_reason` 和 `reason_code`。

### 失败时保留

不要删除失败轮次。至少保留 `evidence.log`、`node-a.log`、`node-b.log`、`*.poll-*.json`、`round-audit.json`、`round-metrics.tsv`、status、路由和清理报告。

## 限制

- `ALLOW_SHARED_NETWORK=1` 只能报告 target-scoped diagnostic；不能代替 dedicated network isolation。
- legacy HTTP/TCP relay 不能证明 TLS、ticket auth 或 release readiness。
- 真实 Direct 通过不能证明所有 NAT 类型都能 Direct；应报告失败率和 reason code。
- 本脚本不提交、不推送、不部署 relay/control，也不自动重启非测试设备。
