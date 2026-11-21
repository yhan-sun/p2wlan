# P2WLAN Flutter 客户端

本项目是 P2WLAN 跨平台客户端的 Flutter 前端实现，配合 Rust 编写的网络核心守护进程（`p2wlan-daemon`）共同构建完整的客户端应用。

## 技术栈与支持平台

- **开发工具链**：Flutter 3.47.2 / Dart 3.13.2（项目根目录 `.fvmrc` 统一指定工具版本）；
- **支持平台**：
  - Windows（x64）
  - macOS 12+（Apple Silicon 与 Intel 架构）
  - Linux（x64 / arm64 桌面环境）
  - Android（API 24+）

## 架构分工

- **Flutter 应用**：跨平台 UI 呈现层，负责用户交互、设置管理、网络启停控制与连接状态展示；
- **Rust `p2wlan-tray`**：轻量级系统托盘组件，常驻后台提供快捷控制，在窗口关闭后维持低内存占用；
- **Rust `p2wlan-daemon`**：底层网络守护进程，负责 TUN 虚拟网卡、WireGuard 协议栈、NAT 穿透、加密中继与本地 IPC。

---

## 本地开发与运行

### 一键启动（macOS）
在 macOS 开发环境中，可以直接运行打包脚本一键编译 Rust 依赖并启动 Flutter 应用：

```bash
./apps/flutter_client/scripts/run_test_app_macos.sh
```

首次点击“启动 P2WLAN”时，系统会弹出管理员授权以允许创建 `utun` 虚拟网络接口。

### 手动构建与运行

1. **编译 Rust 核心依赖**：
   ```bash
   # 编译网络守护进程
   cargo build -p p2wlan-daemon

   # 编译系统托盘伴侣程序
   cargo build -p p2wlan-tray
   ```

2. **启动 Flutter 应用**：
   ```bash
   cd apps/flutter_client
   P2WLAN_DAEMON_BIN=../../target/debug/p2wlan-daemon flutter run -d macos
   ```

> [!TIP]
> 守护进程查找优先级：
> 1. `P2WLAN_DAEMON_BIN` 环境变量；
> 2. 与客户端可执行文件同级的目录；
> 3. macOS 应用包内 `Contents/Resources/p2wlan-daemon`；
> 4. 根工作区 `target/debug` 或 `target/release`；
> 5. 系统 `PATH` 路径。

---

## 诊断与调试接口

桌面守护进程会在本地暴露轻量级 HTTP 诊断接口（默认地址 `http://127.0.0.1:39277`）：
- `GET /health`：存活探活检查；
- `GET /status`：获取当前连接、对端节点与实时路径数据快照；
- `POST /shutdown`：优雅退出守护进程。

---

## 质量验证

在提交改动前，请运行本地代码分析与测试：

```bash
cd apps/flutter_client
flutter analyze
flutter test

# 构建验证（以 macOS 为例）
flutter build macos --release
```
