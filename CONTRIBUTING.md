# 贡献 P2WLAN

## 修改边界

先阅读 [仓库 AI 约束](AGENTS.md) 和 [文档入口](docs/README.md)。修改应归属于实现、测试、部署工具、产品文档或发布契约之一；不要把一次性过程记录写入公共文档。

实现变更必须同时更新直接受影响的测试和稳定文档。文档中的命令、文件名、环境变量、端口和版本规则必须能在当前源码或固定发布包中找到。

## 本地检查

    python3 scripts/docs/verify_repository.py
    bash -n scripts/install-server.sh scripts/deploy-server.sh scripts/p2wlan-server
    cargo fmt --all --check
    cargo test --workspace --all-targets -- --test-threads=1
    (cd server && go vet ./... && go test ./... -count=1)

Flutter、真实 TUN、公网 NAT、双端设备和发布包检查按改动范围执行。没有运行的检查必须在 PR 中明确写出。

## 提交与 PR

提交信息使用 feat:中文 格式，feat: 后不加空格。PR 描述只说明最终行为、验证结果和未覆盖边界；不要把过程报告复制成仓库文档。

发布相关改动必须说明准确源码 SHA、产物摘要、版本嵌入检查和仍需人工完成的设备或安全审计。
