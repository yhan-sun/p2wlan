# P2WLAN Flutter 客户端：HarmonyOS 平台

本目录包含现有 Flutter 客户端的 HarmonyOS ArkTS 宿主，模块声明面向 `phone` 与 `2in1`
设备，应用包名为 `com.p2wlan.client`。界面和业务共用 [lib/](../lib/)，网络引擎源码位于
[client/](../../../client/)。宿主提供 Flutter → UIAbility → VPN Extension → Native/Rust
的 VPN 启停路径、请求级状态回执和启动前的托管网络地址预取。代码接线不代表可发布或已兼容两类设备；
目标构建、签名、安装、授权、网络业务与重启行为仍须分别取得验证证据。四个原生插件也没有鸿蒙实现。

## 工具链

项目版本约束以 [pubspec.yaml](../pubspec.yaml) 为准：Flutter >=3.47.2、
Dart ^3.13.0。其他平台的 [.fvmrc](../../../.fvmrc) 保持原配置。

鸿蒙宿主使用社区 [OH-Flutter 3.47.5-ohos-1.0.0](https://atomgit.com/oh-flutter/flutter_flutter/tree/3.47.5-ohos-1.0.0)，
配套定制 Dart 3.13.4 和同标签引擎工件；需要 DevEco Studio 26.0.0、
HarmonyOS SDK API 26、Node、ohpm、Hvigor 和 Java。不要仅更换普通
Flutter SDK 的版本号，或混用不同标签的 Dart、patched SDK 与引擎。

Rust native 查询 crate 使用 Rust 1.99.0 和
`aarch64-unknown-linux-ohos` target；OHOS target 标准库由 rustup 提供，
linker 和 sysroot 使用所选 DevEco SDK 的 OpenHarmony Native SDK。安装该
target 后，Harmony CMake 阶段调用 [`build_harmony_native.sh`](../../../scripts/build_harmony_native.sh)
构建 Rust cdylib。当前工程只打包 `arm64-v8a`；手机与 2in1 的设备 ABI
和实际运行仍须分别验证。

此工具链的 Dart 依赖包含 SSH Git 地址。无法使用 SSH 的环境可仅在
初始化进程中设置 Git 的 HTTPS 地址映射，不需要更改全局 Git 或 SSH 配置。

## 构建入口

源码目录始终为 `harmony/`。Flutter-OH 的平台标识和固定路径仍为
`ohos`；Studio 同步和 [flutter_harmony.sh](../scripts/flutter_harmony.sh)
共用 [路径适配器](../scripts/harmony_paths.cjs)，自动建立本地
`ohos -> harmony` 符号链接。链接保留供 Studio 后续编译使用、由 Git 忽略，
不复制源码，也不覆盖已有目录。脚本通过构建锁防止多个 Flutter 命令争用。

在 `apps/flutter_client/` 中设置 `FLUTTER_OH_ROOT` 指向兼容工具链，
`DEVECO_SDK_HOME` 指向 DevEco SDK 根目录，`NODE_HOME` 和 `JAVA_HOME`
指向配套运行时。将 Flutter-OH、Node、ohpm、Hvigor 加入 PATH 后执行：

```sh
bash scripts/flutter_harmony.sh pub get
bash scripts/flutter_harmony.sh analyze --no-pub
bash scripts/flutter_harmony.sh test --no-pub
bash scripts/flutter_harmony.sh build hap --debug --no-pub --no-codesign --target-platform ohos-arm64
```

未签名构建输出为 `build/ohos/hap/entry-default-unsigned.hap`。安装前仍需
配置适用的调试签名。`local.properties`、SDK 插件生成的 npm 路径文件、
缓存及 HAP 均为本机构建产物，不进入源码提交。

首次使用先执行上述未签名构建，以准备引擎 HAR、SDK 插件依赖及
`local.properties`；随后用 DevEco Studio 打开本目录并同步。工程显式
使用 `compileSdkVersion`、`compatibleSdkVersion`、`targetSdkVersion`
均为 `26.0.0`，三个版本不得填写空字符串。

## 平台能力边界

Rust 引擎启动时启用 `127.0.0.1:39277` 本地诊断服务，并为本次运行生成随机
Bearer 令牌，原子写入应用私有目录中的 `p2wlan-daemon.diag-auth`，权限为 `0600`。
Flutter 经 `p2wlan/platform` 读取当前令牌后查询引擎状态；令牌不进入设置快照或日志。
停止和启动失败会清理本次令牌；读取失败或格式错误时诊断认证保持失败。

运行时提供 `generateVpnId()` 时使用系统 VPN ID；缺少该方法时生成本地随机 UUID，
仅用于 Native 生命周期的实例隔离，并省略系统配置的 `vpnId`。两种路径都必须实际完成
进程网络保护、系统 VPN 创建和路由确认，才允许引擎进入就绪状态。

ArkTS 通过 `ets/native/build_info.ets` 动态加载
`libp2wlan_harmony_native.so`，查询真实 Rust 构建版本、target、架构和 ABI
版本；缺库、ABI 不匹配与 native 调用失败有固定错误码。VPN 生命周期桥接只通过 MethodChannel
传送 request ID、配置 revision 和停止关联字段；token 与网络配置留在应用私有快照中。VPN Extension
在系统 VPN 授权与进程保护后调用 Rust Control 预取托管设备地址及权威 CIDR，再据此构建系统地址/路由，
并把同一配置交给 daemon。缺少服务端 CIDR、响应不匹配、配置版本变化或未取得匹配的状态回执时均失败关闭。
停止命令通过同一私有目录中的短时一次性文件传递，因为 Extension 销毁回调没有可依赖的 stop 参数；
Native `OwnedFd` 只有在 Rust 确认停止后才交还系统。该代码路径已有 Flutter 与 Rust host 回归，
ArkTS/N-API/Harmony 构建及手机/2in1 实际运行仍以对应构建和设备记录为准。
DevEco 26 的 `VpnConfig` 将 MTU 限制在 576–1500；超出该范围时 Harmony Extension
返回网络配置错误，不会单独改写系统隧道 MTU 造成其与 Rust 数据面配置不一致。

当前 [app_links 7.2.1](https://pub.dev/packages/app_links/versions/7.2.1)、
[window_manager 0.5.2](https://pub.dev/packages/window_manager/versions/0.5.2)、
[tray_manager 0.5.3](https://pub.dev/packages/tray_manager/versions/0.5.3)、
[url_launcher 6.3.2](https://pub.dev/packages/url_launcher/versions/6.3.2)
没有声明 ohos 原生实现，因此生成的鸿蒙插件注册表为空。应用启动时会跳过
`app_links`，鸿蒙暂不支持房间深链；外部链接、窗口和托盘仍需适配。

登录凭据和设置通过 `p2wlan/platform` MethodChannel 写入 UIAbility 的
`Context.filesDir/p2wlan` 私有目录。宿主桥接不可用时，Dart 存储会失败关闭，
不会回退到系统临时目录。该路径已通过代码级测试，仍需在目标鸿蒙环境验证。

系统 VPN 授权、TUN fd、socket 保护、路由、Rust 生命周期和 phone/2in1 运行验收
仍须以目标 SDK 构建及设备证据确认。本目录遵循 [AGENTS.md](../../../AGENTS.md) 和
[贡献规则](../../../CONTRIBUTING.md)。
