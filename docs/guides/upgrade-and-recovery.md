# 升级与恢复

## 升级

每次升级只使用一个固定 server-vX.Y.Z 归档：

    sudo p2wlan-server backup
    sudo p2wlan-server update --version server-vX.Y.Z
    sudo p2wlan-server verify --service all
    sudo p2wlan-server check --service all
    sudo p2wlan-server doctor --service all

升级保留已有配置和数据。当前 manager 在激活新发布前检查支持日志配置：`LOG_UPLOAD_DIR` 缺失或为空时，仅追加数据目录下 `log-uploads` 的绝对路径；非空自定义值保持原样。它只创建或恢复受管理的最后一级目录，不递归修改数据文件；符号链接、其他用户属主、配置锁冲突或配置在检查期间被替换时拒绝继续。准备过程只解析完整的单行环境赋值；任意变量使用多行引号或反斜线续行时，报告 `unsupported_environment_syntax` 并在更改目录和配置前停止，不把其他变量中的文本误作配置项。准备失败不会切换当前发布。更新前后记录准确版本、源码提交、归档 checksum、服务健康检查和 doctor 结果。doctor 的主机级检查仍不替代真实客户端/TUN/公网入口验收。

旧版 manager 自身不具备新增的准备逻辑。升级遗留安装时，先从已校验的新归档安装其中的 `p2wlan-server`，再运行该版本的 update；上传部署入口会在 update 前安装同归档的 manager。已有自定义日志目录不会被自动接管，须由部署者按原路径核对访问权限。该补齐过程不会轮换 JWT、管理台、Relay 或 TLS 凭据。

Control 重启或版本更新时，保留原来的 `control.env`（尤其是 `JWT_SECRET`）和 `DB_PATH` 指向的持久数据库，已有的有效账号登录和设备凭据可继续使用，客户端会自动恢复控制连接，无需重新输入密码。重启期间控制请求和信令会暂时不可用，这不等于退出登录，也不承诺数据连接完全无中断。数据库暂时不可用时，认证接口返回可重试的 `503 authentication_unavailable`；凭据到期、主动撤销、房间撤权或真正过时的设备注册仍按原认证与围栏规则拒绝。

## 备份

backup 使用服务端内置的 SQLite 一致性快照工具，不按顺序复制在线的主文件、WAL 和 SHM。数据库路径读取 Control 的 DB_PATH；相对路径相对于服务数据目录。备份目录包含数据库摘要、完整性检查结果、schema 版本和当前发布元数据。

配置含有秘密。需要把配置一起保存时，使用独立于备份包的 age 私钥：

    sudo p2wlan-server backup --include-config --age-recipient age1example

age 私钥不放在服务器备份目录、同一个归档或命令行中。没有加密接收方时，backup 只保存数据库快照和恢复所需的非秘密元数据。

## 恢复

恢复要求 systemd 可用，并在替换数据库前验证 checksum、SQLite integrity_check 和备份元数据：

    sudo p2wlan-server restore --backup /var/lib/p2wlan/backups/p2wlan-YYYYMMDDTHHMMSSZ

如果备份包含加密配置，显式提供离线保存的 age identity：

    sudo p2wlan-server restore \
      --backup /var/lib/p2wlan/backups/p2wlan-YYYYMMDDTHHMMSSZ \
      --age-identity /secure/recovery-key.txt

恢复前会为当前数据库创建一致性 pre-restore 快照，并保存现有 Control/Relay 配置和两项服务的运行状态。服务原本运行时会在替换数据前严格停止对应服务；停止失败立即中止。恢复后的启动或健康检查失败时，manager 会恢复 pre-restore 数据库、原配置和原服务状态；如果这一步也无法完整完成，会保留 recovery copy 并明确报错，不会把部分恢复状态报告为成功。服务原本未运行时不会擅自启动。恢复完成后仍须执行登录、房间、票据、撤权和双端通信验证。

## 回滚

    sudo p2wlan-server rollback --version server-vX.Y.Z
    sudo p2wlan-server check --service all

回滚只切换到已经安装的发布目录，并检查版本和健康状态，不自动把新 schema 降回旧 schema。新版本写入数据后，旧版本可能不兼容；此时应恢复兼容的数据库快照或向前修复，不应承诺无损自动降级。
