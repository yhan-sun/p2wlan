# 升级与灾难恢复

本指南面向自托管服务端管理员，介绍 P2WLAN 服务端（Control 与 Relay）的版本平滑升级、数据备份、恢复与故障回滚操作。

---

## 1. 平滑升级

原生 systemd 部署环境提供了全自动的在线更新工具。在执行升级前，推荐先进行一次数据备份：

```bash
# 1. 备份当前数据
sudo p2wlan-server backup

# 2. 执行版本升级（指定目标服务端版本 tag）
sudo p2wlan-server update --version server-vX.Y.Z

# 3. 校验并检查升级后的服务健康状态
sudo p2wlan-server verify --service all
sudo p2wlan-server check --service all
sudo p2wlan-server doctor --service all
```

升级过程会保留您现有的全部配置与数据库，并平滑重启服务。

> [!TIP]
> 如果您采用的是 Docker Compose 部署，升级只需要在部署目录（如 `/opt/p2wlan-docker`）修改 `.env` 中的镜像版本标签，然后执行：
> ```bash
> sudo docker compose pull
> sudo docker compose up -d
> ```

---

## 2. 数据备份

P2WLAN Control 内置了专为 SQLite 打造的一致性快照备份工具。它会在事务一致性边界内安全生成数据库快照，避免因直接拷贝在线的 `.db` 和 WAL 文件导致数据损坏。

### 基础数据备份
```bash
sudo p2wlan-server backup
```
备份产物默认保存在 `/var/lib/p2wlan/backups/` 目录下，包含数据库一致性快照、完整性校验值（SHA-256）与元数据。

### 加密备份配置文件
如果希望将敏感配置文件（包含 JWT 密钥、Admin Token 等）一并打包备份，可以使用 `age` 工具进行公钥加密：

```bash
sudo p2wlan-server backup --include-config --age-recipient age1example...
```
配置文件在写入备份包前会使用指定的公钥加密，确保即使备份文件离线存储也能防止密钥泄露。

---

## 3. 灾难恢复

当遇到硬件故障、误操作或迁移服务器时，可以使用备份文件快速还原系统：

### 从基础备份恢复
```bash
sudo p2wlan-server restore --backup /var/lib/p2wlan/backups/p2wlan-YYYYMMDDTHHMMSSZ
```

### 恢复包含加密配置的备份
如果备份包包含了加密配置，需提供对应的私钥文件路径解密：

```bash
sudo p2wlan-server restore \
  --backup /var/lib/p2wlan/backups/p2wlan-YYYYMMDDTHHMMSSZ \
  --age-identity /path/to/recovery-key.txt
```

> **自动安全保护机制**：
> 在执行还原前，系统会自动对当前运行中的数据库做一份预还原快照（Pre-restore snapshot）。若还原或启动过程出现异常，系统会自动安全回滚至当前状态，避免产生半写入的不一致数据。

---

## 4. 版本回滚

如果升级到新版本后发现异常，可快速回滚至上一版本：

```bash
# 回滚至指定的历史版本
sudo p2wlan-server rollback --version server-vX.Y.Z

# 检查回滚后的服务状态
sudo p2wlan-server check --service all
```

> [!NOTE]
> 回滚操作会切换运行程序二进制并重启服务。如果新版本包含了不可逆的数据库迁移（Schema 变更），回滚后建议配合对应版本的数据库备份进行完整还原。
