# CLI 参考

| 命令 | 作用 |
| --- | --- |
| p2wlan config set control URL | 设置 Control 地址 |
| p2wlan config show | 查看非秘密配置 |
| p2wlan login -u USER | 登录或注册当前账号 |
| p2wlan account show | 显示当前账号身份 |
| p2wlan up / down | 启动或停止虚拟网络 |
| p2wlan status [--json] | 查看 daemon、设备和路径状态 |
| p2wlan doctor | 输出结构化诊断摘要 |
| p2wlan room list | 列出房间 |
| p2wlan room connect ID | 连接房间 |
| p2wlan room disconnect ID | 断开房间 |
| p2wlan route verify / repair | 检查或修复本机路由 |
| p2wlan logs -f | 跟随 daemon 日志 |
| p2wlan support-bundle | 生成本地支持包 |
| p2wlan support-bundle --upload | 经用户确认后上传支持包 |
| p2wlan update | 按当前安装源更新 |

准确参数以 p2wlan help 和当前 Release 内的 CLI 为准。登录、配置和查询不要使用 sudo；创建 TUN、路由和 systemd 服务可能需要权限。
