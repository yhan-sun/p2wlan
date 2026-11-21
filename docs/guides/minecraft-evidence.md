# Minecraft 交互采证工具

本篇文档介绍 `scripts/dual-end/` 下提供的 Minecraft 自动化协议交互与验证套件。该工具集用于在真实的 P2WLAN 虚拟局域网环境中，自动化验证游戏数据包在虚拟网络上的收发与业务可达性。

---

## 1. 支持的游戏版本与适配器

| 游戏平台 | 协议版本 | 运行依赖 | 适配器脚本入口 |
| --- | --- | --- | --- |
| **Java Edition** | 1.20.4 (协议号 765) | Node.js 22.16.0 | `scripts/dual-end/minecraft-adapters/java-adapter.js` |
| **Bedrock Edition** | 1.18.30 (协议号 503 / RakNet 10) | Node.js 26.0.0 | `scripts/dual-end/minecraft-adapters/bedrock/bedrock-adapter.js` |

适配器负责以程序化方式模拟客户端与服务端完成游戏握手、登录、进入世界以及基础方块交互（`block_place`），并将真实的网络往返状态记录为结构化证据。

---

## 2. 本地依赖安装与单测验证

两个适配器具备独立的依赖管理，使用对应的 Node.js 版本运行以下测试：

```bash
# 测试 Java 适配器
cd scripts/dual-end/minecraft-adapters
npm ci --ignore-scripts
npm test

# 测试 Bedrock 适配器
cd ../minecraft-adapters/bedrock
npm ci --ignore-scripts
npm test
```

---

## 3. 运行端到端采证监督器

采证套件通过 POSIX 监督器 `minecraft_interaction_runner.py`（基于 Python 3.11+）启动适配器并收集执行状态：

```bash
python3 scripts/dual-end/minecraft_interaction_runner.py \
  --manifest /path/to/manifest.json \
  --adapter-argv '["/path/to/node", "/path/to/checkout/scripts/dual-end/minecraft-adapters/bedrock/bedrock-adapter.js", "--config", "/path/to/config.json"]' \
  --timeout-ms 10000 \
  --output /path/outside/repository/runner-result.json
```

监督器负责进程树生命周期管理、超时回收与结果归约，输出端到端延迟统计（RTT）与交互成功率报告，为多人联机网络的稳定性验证提供客观数据支持。
