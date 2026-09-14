# 连接生命周期

连接的有效状态由多个有界身份共同决定：daemon 进程、网络 generation、peer session、remote candidate epoch、Relay connection 和 Direct validation owner。旧任务完成时必须先检查它仍属于当前 owner，不能清除新连接的状态。

生命周期顺序是：

    注册 → 获取候选 → 建立 Control/Relay 信令 → 加密确认 → 选择 Direct 或 Relay → 持续刷新 → 网络/身份变化后重新验证 → 离开或撤权

Relay 已确认可用时，Direct 探测失败或候选刷新不能直接清除 Relay。Direct 只有当前候选和加密业务确认成功后才替换 Relay。撤权、离开房间、地址改变、进程替换和网络 generation 变化会使旧会话失效。

诊断状态按进程和 revision 防止旧快照覆盖新状态。Connecting、在线设备数量、加密 ACK、收包计数和业务可达性分别表示不同层级；最终判断必须使用实际虚拟 IP 业务验证。
