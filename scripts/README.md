# P2WLAN 脚本目录

这里的脚本按用途分层。真实双机验收、NAT-sim 回归和发布身份校验不能互相替代。

## 主要入口

| 入口 | 用途 | 是否真实双机 | 说明 |
|---|---|---:|---|
| `dual-end/mini-air-smoke.sh` | Mini/Air 真实 daemon、真实 TUN、Direct/relay 证据 | 是 | 真实远端动作必须显式设置两个授权变量 |
| `dual-end/dual-end-smoke.sh` | 本机 loopback 双 daemon 冷启动回归 | 否 | 使用本地 control/STUN，默认禁用 TUN |
| `dual-end/field-gate-verify.sh` | 只读解析既有双机 artifact | 否 | 不启动 daemon，不修改远端 |
| `dual-end/run-ab-sequence.sh` | compat 3 轮、strict preflight 3 轮、strict acceptance 10 轮 | 是 | 必须显式提供 control、network 和 legacy baseline |
| `nat-sim/nat-sim-smoke.sh` | Direct、relay-only、慢 relay、failover、故障注入回归 | 否 | 不能代替 Mini/Air 实测 |
| `outbound-liveness/live_check.sh` | UDP outbound liveness blocked/normal 检查 | 取决于参数 | 只用于 liveness 证据，不等同 Direct 成功 |
| `release/verify_release_identity.py` | build-info、版本、commit、SHA 和 dirty gate | 否 | release workflow 的 fail-closed gate |
| `staging/validate_staging_config.py` | staging catalog、TLS、audience/region 和 key 配置校验 | 否 | 默认只读，不部署、不重启 |

每个主要入口旁边都有同名 Markdown，例如 `mini-air-smoke.sh` 对应
`mini-air-smoke.md`。Markdown 记录前提、用法、输出字段、结果解释和限制。

## 双机脚本的共同安全规则

- 未同时设置 `ALLOW_STAGING_TEST=1` 和 `ALLOW_REMOTE_RESTART=1` 时，真实双机脚本只能 dry-run。
- `REAL_TUN=1` 才能把真实 TUN 业务回包作为生产数据面证据。
- `ALLOW_SHARED_NETWORK=1` 只能用于明确标记的共享网络诊断，不能报告为隔离验收。
- `ALLOW_LEGACY_PLAINTEXT_RELAY=1` 只允许诊断当前 legacy HTTP/TCP 环境，不能报告 TLS relay 通过。
- 密码、token、ticket、私钥和完整 Authorization header 不应出现在命令行日志或 artifact。
- `PERSIST_PRIVILEGED_SUPERVISOR=1` 只复用本次授权 supervisor；它不是永久系统服务，机器重启或 supervisor 退出后需要重新授权。

## 结果目录

双机脚本应把每次运行写入独立的 `ARTIFACT_ROOT/<run-id>/`，并保存命令、版本身份、git 状态、双端日志、status、timeline、路由、overlay 输出和逐轮指标。重复使用 artifact 目录会被脚本拒绝。

`target/` 下的临时 artifact 不属于发布输入；发布前必须重新生成并通过 release identity gate。
