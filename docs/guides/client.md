# 客户端指南

## 安装与配置

优先使用 GitHub Release 的固定版本包。安装脚本只负责安装公开的客户端文件，不包含 Control 地址、账号或凭据。

常用 CLI：

    p2wlan config set control https://control.example.com
    p2wlan config show
    p2wlan login -u your-name
    p2wlan up
    p2wlan down
    p2wlan status

登录和配置不要使用 sudo；创建 TUN、路由或系统服务时，CLI 会在需要的位置请求权限。

## 路径和路由

    p2wlan doctor
    p2wlan route verify
    p2wlan route repair
    p2wlan logs -f

CLI 展示的是 daemon 已确认的状态。Connecting 不等于业务可用，Direct/Relay 标签也不等于对端应用已经收到数据；需要用虚拟 IP 执行实际的 TCP、UDP 或 ICMP 验证。

## 支持包

支持包用于用户主动提交诊断。上传前检查压缩包和日志，删除不必要的业务信息，确认接收方和保留期限。不要上传 JWT、设备凭据、Relay ticket、私钥、完整环境文件或真实主机密钥。

没有获得明确上传授权时，只保留本地文件并通过安全渠道交给管理员。支持包行为和服务端保存目录由当前实现与部署策略共同决定。
