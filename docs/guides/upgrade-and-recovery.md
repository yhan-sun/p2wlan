# 升级与恢复

## 升级

每次升级只使用一个固定 server-vX.Y.Z 归档：

    sudo p2wlan-server backup
    sudo p2wlan-server update --version server-vX.Y.Z
    sudo p2wlan-server verify --service all
    sudo p2wlan-server check --service all

升级不会覆盖配置目录和数据目录。更新前后记录准确版本、源码提交、归档 checksum 和健康检查结果。

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

服务原本运行时，恢复会严格停止 Control、替换数据库、恢复配置并恢复原状态；停止失败会中止，不会继续复制。服务原本未运行时，恢复不会擅自启动它。恢复完成后仍须执行 check 和登录、房间、票据、撤权、双端通信验证。

## 回滚

    sudo p2wlan-server rollback --version server-vX.Y.Z
    sudo p2wlan-server check --service all

回滚只切换到已经安装的发布目录，并检查版本和健康状态，不自动把新 schema 降回旧 schema。新版本写入数据后，旧版本可能不兼容；此时应恢复兼容的数据库快照或向前修复，不应承诺无损自动降级。
