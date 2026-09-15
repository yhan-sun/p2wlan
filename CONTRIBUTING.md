# 贡献 P2WLAN

## 修改边界

先阅读 [仓库 AI 约束](AGENTS.md)、[文档入口](docs/README.md) 和 [工程质量与架构边界](docs/explanation/engineering-quality.md)。修改应归属于实现、测试、部署工具、产品文档或发布契约之一；不要把一次性过程记录写入公共文档。

实现变更必须同时更新直接受影响的测试和稳定文档。文档中的命令、文件名、环境变量、端口和版本规则必须能在当前源码或固定发布包中找到。

连接、并发和数据面修改必须先确定状态所有者，再修改代码。跨异步边界缓存状态时使用 generation、revision、incarnation、session identity 或 owner token 等 fencing identity，在真正产生副作用前再次验证。新增队列、锁、缓存、重试和后台任务必须有容量、deadline、取消条件和可观测失败原因。

不要为了缩短文件机械抽象。有效拆分应隔离状态所有权、副作用、协议编码或可独立测试的决策逻辑。现有历史热点采用源码体积棘轮，只允许缩小，不允许继续扩大。

## 本地检查

    python3 scripts/docs/verify_repository.py
    python3 scripts/quality/check_code_health.py
    python3 scripts/quality/test_code_health.py
    bash -n scripts/install-server.sh scripts/deploy-server.sh scripts/p2wlan-server
    cargo fmt --all --check
    cargo test --workspace --all-targets -- --test-threads=1
    (cd server && go vet ./... && go test ./... -count=1)

Flutter、真实 TUN、公网 NAT、双端设备和发布包检查按改动范围执行。没有运行的检查必须在 PR 中明确写出。

## 提交与 PR

提交信息使用 feat:中文 格式，feat: 后不加空格。PR 描述只说明最终行为、验证结果和未覆盖边界；不要把过程报告复制成仓库文档。

涉及连接、并发、持久化或数据面的 PR 必须说明状态所有者、fencing identity、资源上界、失败发生在 transport handoff 的哪个阶段、是否影响 Direct/Relay/rekey/replay/MTU/room authorization，以及覆盖了哪些超时、取消、重复、过期和竞争测试。

发布相关改动必须说明准确源码 SHA、产物摘要、版本嵌入检查和仍需人工完成的设备或安全审计。
