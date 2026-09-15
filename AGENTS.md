# P2WLAN 仓库 AI 约束

本文件是仓库级工作契约。任何 AI 或自动化代理在修改本仓库前都必须遵守它；与实现、测试和安全边界冲突的临时说明不具有更高优先级。

## 开始工作前

1. 运行 git status --short --branch，确认当前分支和工作区，不覆盖已有改动。
2. 阅读本文件、agent skill（skills/p2wlan-repository/SKILL.md）、docs/README.md 和 docs/explanation/engineering-quality.md。
3. 列出并阅读当前 docs/ 下的全部 Markdown 文档，再决定文档归属或删除。文档任务不得只凭文件名或旧报告判断。
4. 阅读受影响实现、测试、脚本和 workflow；命令、参数、路径和默认值以它们为准。

## 内容硬约束

- 公共文档只描述当前可用行为、稳定规则、限制和可复现操作。
- 不提交个人主机名、IP、域名、用户名、主目录、SSH 文件名、凭据、日志、截图中的秘密或本机开发过程。
- 不把阶段汇报、交接记录、事故流水、一次性验收台账或“从 1 改为 2”的过程叙述换名放进 docs/、archive/ 或历史标签页面。
- 产品文档、部署工具、开发记录和发布证据分开：代码和脚本负责执行，PR/Issue 记录过程，Release 资产保存版本绑定证据。
- 文档中的每条命令都必须能在干净 checkout 或明确的发布包中找到执行入口；不能用空文件、跳过测试或未验证的承诺让链接变绿。
- 删除或移动文档时同步修复 README、脚本、测试和 workflow 的引用。
- 未实际运行的测试不得写成“已通过”；未完成的真实设备、公网或安全审计必须明确标注为未完成。

## 代码硬约束

- 一个连接正确性事实只能有一个权威状态所有者；其他模块只能持有带 fencing identity 的快照，不得维护可独立演进的第二份真相。
- 跨 await、channel、任务或缓存传递的可变网络状态，在真正执行发送、提交、提升或持久化前必须重新验证 generation/revision/incarnation/session/owner identity。
- 新增队列、缓存、重试、后台任务必须有明确容量、生命周期、取消条件和结构化失败原因；禁止无限增长和静默丢弃。
- 默认不允许持锁执行网络 I/O、sleep、外部回调或无上界 await。因 counter/order 等协议不变量必须跨 await 持锁时，必须有明确 timeout、解释和竞争测试。
- 生产路径不得用 panic 处理可由网络、用户输入、远端状态、磁盘或正常生命周期竞争触发的失败。
- 不允许通过字符串日志驱动控制流；预期失败使用类型化错误或稳定 reason code。
- 不为了“拆文件”制造 facade、循环依赖或共享内部锁。拆分必须隔离状态所有权、副作用、协议编码或可独立测试的决策逻辑。
- `scripts/quality/check_code_health.py` 是复杂度棘轮。历史热点相对 PR 基线只能缩小；新增生产模块必须保持在统一预算内。体积门禁不代表逻辑或并发正确性。

## AI 交付要求

每次修改完成后，至少运行：

    python3 scripts/docs/verify_repository.py
    python3 scripts/quality/check_code_health.py --base-ref main
    python3 -m unittest discover -s scripts/quality/tests -p 'test_*.py'
    bash -n scripts/install-server.sh scripts/deploy-server.sh scripts/p2wlan-server

再按改动范围运行 Rust、Go、Flutter 或脚本测试，并在交付时说明未运行的项目。提交信息必须使用 feat:中文 格式，feat: 后不加空格。
