# 排障指南

先记录客户端、daemon、Control、Relay 的准确版本和时间，再按层排查。

| 现象 | 先检查 | 不要据此下结论 |
| --- | --- | --- |
| 无法登录 | Control URL、HTTPS 证书、账号响应、时间 | 不能仅凭 Relay 正常判断 Control 正常 |
| 登录成功但无设备 | 房间成员、设备授权、Control 信令和本地 daemon | UI 在线不等于 TUN 已建立 |
| Direct 不通 | NAT profile、候选来源、UDP 防火墙、路径 reason code | STUN 成功不等于对端可入站 |
| 只有 Relay | Relay TLS、audience/region、ticket、/readyz、撤权 feed | Relay 路径不说明 Direct 一定有缺陷 |
| 虚拟 IP 可见但业务不通 | 本机路由、房间租约、数据面收发计数、目标应用监听和防火墙 | 加密 ACK 或在线人数不等于业务往返 |
| 重启后状态错误 | daemon process/revision、网络 generation、peer session、房间授权 | 旧快照不能当作实时状态 |

建议命令：

    p2wlan --version
    p2wlan status --json
    p2wlan doctor
    p2wlan route verify
    p2wlan logs -f

支持包上传必须由用户显式确认。上传前移除不必要的业务日志和环境文件，保留能解释问题的 reason code、版本、时间和脱敏状态。
