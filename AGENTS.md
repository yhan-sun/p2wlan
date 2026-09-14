# P2WLAN 仓库 AI 约束

本文件是仓库级工作契约。任何 AI 或自动化代理在修改本仓库前都必须遵守它；与实现、测试和安全边界冲突的临时说明不具有更高优先级。

## 开始工作前

1. 运行 git status --short --branch，确认当前分支和工作区，不覆盖已有改动。
2. 阅读本文件、agent skill（skills/p2wlan-repository/SKILL.md）和 docs/README.md。
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

## AI 交付要求

每次修改完成后，至少运行：

    python3 scripts/docs/verify_repository.py
    bash -n scripts/install-server.sh scripts/deploy-server.sh scripts/p2wlan-server

再按改动范围运行 Rust、Go、Flutter 或脚本测试，并在交付时说明未运行的项目。提交信息必须使用 feat:中文 格式，feat: 后不加空格。
