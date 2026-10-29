# 运维指南

## 服务

    sudo p2wlan-server status --service all
    sudo p2wlan-server start --service all
    sudo p2wlan-server stop --service all
    sudo p2wlan-server restart --service all
    sudo p2wlan-server check --service all
    sudo p2wlan-server doctor --service all

Control 的 /health 只表示进程可响应；Relay 的 /readyz 还要求撤权 feed 已同步并在有效时间内。`check` 用于服务级健康判定；`doctor` 额外检查发布包、systemd、Admin 凭据、支持日志配置与主机目录权限、SQLite、Relay TLS、备份和数据盘空间，并把非致命项标成 warning。两者都不能证明真实公网入口、TUN 或应用业务已经端到端可达。

## 管理控制台

Control 可选提供 `/admin/` 只读管理台。只有配置独立的 `CONTROL_ADMIN_TOKEN` 后该入口才存在；未配置时 `/admin` 与 `/admin/*` 返回 404。管理员令牌至少 32 个字符，通过 `Authorization: Bearer` 访问管理 API，不复用账号 JWT、设备凭据或 Relay 凭据。

登录验证超过 15 秒会结束等待并提示重试；请求期间不接受重复提交，离开登录页会取消尚未完成的验证。浏览器必须允许此站点使用会话存储才能保存登录态；无法保存时明确报错，不转入已登录界面。主题、语言和密度偏好在本地存储不可用时仍可在当前页面切换。

管理台按概览、资源、运维组织导航。概览优先显示最近一小时内前 5 条待关注连接，并可直接进入对应方向的详情；没有设备、尚无观测和当前没有提醒分别呈现，不据此声称业务已验证可达。资源区可查看账号、设备、网络与房间，运维区提供连接排障和运行状态。账号详情先读取摘要，设备、网络、房间分别分页，关系图只在进入关系视图后请求。原先的“拓扑”入口现在明确命名为“资源关系”：全局和单账号关系图都只来自 Control 已提交关系，包括账号到网络/房间的 membership、网络到设备的 attachment，以及可选显示的数据库待处理 signaling。单账号关系图会保留共享网络或房间里的对端账号与设备，不会把共享关系错误裁掉。

账号、设备、网络和房间主列表使用 `pagination=cursor` 的快照游标。游标绑定资源类型、搜索词、在线筛选和账号范围；更换筛选时从首页读取，旧游标跨范围复用返回 400。每页最多 200 条，响应包含 `generated_at` 和 `snapshot_at`。创建时间晚于快照边界的实体不会进入后续页；已经存在的记录仍反映每次读取时的更新与删除，不提供跨请求历史 MVCC。创建时间以秒记录，首个快照采用上一完整秒，因此刚创建的实体可能需要稍后从首页刷新。网络和房间支持按名称、ID、网段或房间码搜索，账号范围按成员关系过滤；筛选在分页之前应用。「全部网络」包含「房间网络」。原有 `/accounts/cursor`、`/devices/cursor` 和 offset 接口保留兼容，不能互换游标。

全局资源关系默认按 `view=summary` 分阶段读取账号、网络/房间和 membership；「包含设备与信令」使用 `view=full`。每页只读取有界源记录，通过固定快照的游标继续；页面按需加载更多，不定时重新遍历全图。浏览器最多保留 64 页、2000 个节点和 4000 条边，达到预算时明确显示部分数据并提示限定账号。切换视图或离开页面会取消不再需要的请求。摘要视图不把尚未读取的设备数量显示为零；进入资源后独立读取成员和设备。账号内的资源索引保留服务端搜索和按需分页，单个网络深链不依赖全局图是否加载完成。

默认个人设备按所属账号单独分组，保留账号到设备的私有挂载关系，不生成跨账号的共享默认网络。资源列表搜索与进入分组后的成员/设备搜索分别保存，网络名称不会被继续用来过滤该网络的设备。

摘要关系图通过快照范围内的设备存在性标记呈现个人分组，无需提前加载全部设备。待处理信令数量与可选关系边只包含仍在 120 秒投递期限内的记录。全局关系图明确显示手动快照状态，由刷新或继续加载更新。

资源关系图中的账号颜色只用于稳定区分身份；设备的绿色/灰色状态点表示 Control 记录的 online 状态；待处理 signaling 默认隐藏，打开后以琥珀色虚线显示。搜索会只保留匹配资源及其一跳上下文，避免把不相关分支继续留成低透明度“毛线团”。资源关系图只展示 Control 确认的资源拓扑，不会把 `relay_rtt_ms`、候选信息或 signaling 猜测推断成数据面连接。真实数据面活动路径完全由各 daemon 端点权威上报并持久化，不与资源关系图混淆。

管理台还展示 Control 数据库和当前 Control 进程能直接确认的网络、房间、设备、活动隧道、待处理信令和构建信息。设备的 `online`、Relay RTT 或 Control 健康状态都不能单独证明虚拟 IP 业务已经双向可达。

### Connections 与路径观测

管理台的 **连接排障** 工作区提供待关注、全部观测、连接拓扑与历史趋势四个视图；它与“资源关系”保持分离：资源关系回答账号、网络、房间和设备之间的 membership / attachment；Connections 只读取客户端 daemon 已提交并由 Control 持久化的单向活动路径观测，不根据 signaling、Relay RTT 或 membership 推断 Direct / Relay。

Connections 默认使用列表视图，支持服务端搜索设备名、账号名或网络名，并按 `network_id`、`account_id`、`device_id`、`path`（direct / relay / none）与 `freshness`（fresh / stale）过滤。`GET /admin/api/v1/connections` 使用 `limit` / `offset` 分页。条目始终保持方向性：`A → B` 与 `B → A` 是两个独立观测；stale 或 reporter offline 的记录只表示最后一次已知路径，不等于当前仍存在活动连接。

选择单个网络后可切换到 Live Topology。列表与拓扑共用 freshness 筛选；过期观测使用弱化虚线，不作为当前路径证据。无 committed path 的观测通过单独清单提供详情入口，不绘制虚构路径边。大规模网络受前端明确的连接预算保护，达到预算会提示收紧搜索或路径过滤，不会静默把局部图声称为完整网络。

点击连接列表行或拓扑边会打开当前方向的只读详情与迁移时间线。详情同时按同一网络、交换后的上报端和远端精确查询反方向，分别展示路径、时间、新鲜度和恢复状态；反方向缺少报告、离线或读取失败均单独说明，不据此推断双向可达。`GET /admin/api/v1/connection-transitions` 按 `reporting_device_id`、`remote_device_id`、`network_id` 查询，并使用 `limit` / `cursor` 分页；每对设备最多保留 50 条最近迁移记录。路径观测仍不证明远端具体应用端口一定可达，最终业务判断需要实际虚拟 IP 流量验证。

### Connection Health 与 attention signals

`GET /admin/api/v1/connection-health` 在请求时从 latest authoritative observations 和受限 transition history 派生运维信号，不新增独立 health 状态机，也不持久化告警状态。接口支持 `network_id`、`account_id` / `user_id`、`device_id` 作用域；`window_seconds` 默认 3600 秒，可选 60–86400 秒；`limit` 默认 50、最大 100，配合 `offset` 对 attention connections 分页；`signal` 可从下列固定 signal 中选择一种。提醒按严重程度、最新证据时间、方向和网络 ID 排序。`alerts_total` 表示类型筛选后的总量，`alerts_unfiltered_total` 表示同一作用域内筛选前的提醒总量，`alerts_offset` 表示当前起点；summary 始终统计所选账号、网络、设备范围，不随提醒类型筛选缩小。每次请求读取同一事务快照，后续刷新或翻页仍可能受到新上报的影响。

summary 分开统计 fresh、stale、reporter offline、fresh Direct、fresh Relay、`fresh_online_no_path`，以及窗口内 Direct↔Relay path switch、显式 Direct/Relay failure reason 和 validation RTT 样本。`fresh_online_no_path` 只统计 lifecycle=`online` 且没有 committed path 的 fresh observation。Relay 本身是正常路径类别，不会因为当前路径为 Relay 就产生告警；`last_validation_rtt_ms` 及其聚合也只表示最近一次验证样本，不是持续实时 RTT。

attention signal 是固定、可解释的条件：

- `reporter_offline`：上报端 heartbeat lease 已失效；
- `stale_observation`：上报端仍在线，但最新路径观测已超过 freshness lease；
- `no_active_path`：观测仍 fresh、peer lifecycle 为 `online`，但 daemon 没有 committed active path；明确 `offline` / `unbound` 的 peer 没有路径不会被误报；
- `frequent_path_switching`：请求窗口内至少 4 次已记录的 Direct↔Relay 切换；
- `repeated_path_failures`：请求窗口内至少 3 次显式 `direct_probe_failed` / `direct_path_failed` / `relay_path_failed`。

阈值会随响应一起返回，不作为隐藏评分。transition history 每个方向最多保留 50 条，因此在极端高频切换超过保留上限时，窗口派生计数可能是下界；该接口不应被解释为完整长期时序分析。

管理台在 **连接排障 → 待关注** 消费该接口，保留 `/admin/health` 兼容入口。Dashboard 展示最近 1 小时的摘要及前 5 条提醒；待关注视图支持按账号、网络、设备范围查看 1h / 6h / 24h 窗口，直接展示 fresh / stale / reporter offline、Direct / Relay、online-no-path、路径切换、显式失败与 validation RTT 样本。页面不会计算综合健康分，也不会把 Relay 本身着色成故障。

Needs attention 列表逐条显示服务端返回的固定 signal 和阈值相关计数。点击某一项会读取相同 `(network, reporting device, remote device)` 的最新 directional Connection，并打开与 Connections 工作区共用的只读详情 / transition timeline；Health UI 不维护第二份连接详情或路径状态。

### Connection Trends

`GET /admin/api/v1/connection-trends` 提供 1 小时粒度、最多 30 天的只读长期趋势基础数据。默认 `window_hours=24`，允许 1–720；可传 `network_id` 下钻单个 network，不传时按小时聚合所有 network。

趋势字段包括 accepted committed-observation samples、Direct/Relay/no-path samples、真实 Direct↔Relay switch、显式 Direct/Relay failure，以及 validation RTT count/average/max、固定 histogram 和 p50/p95 histogram upper bound。这里的 observation samples 不是路径在线时长比例；duplicate/rejected、显式 resync 与新 registration owner 的首个重同步快照不制造趋势样本。p50/p95 也不是原始 RTT 明细计算出的精确分位数。超过 10 秒的 RTT 进入 overflow bucket，超过 24 小时的异常输入直接忽略；如果目标 percentile 落入 overflow，API 不返回虚假的数值上界。

小时 rollup 每个 network 每小时只有一行并保留 720 小时；不会长期保存 peer/device 级事件明细。管理台的历史趋势视图提供最近 24 小时、7 天或 30 天的趋势图，可随网络筛选查看路径观测样本、切换与显式失败，以及平均 RTT 和 P95 分桶上界；小时明细支持键盘操作。没有 RTT 样本的小时保持空缺，P95 超出最高分桶时明确标识为大于 10000 ms，不绘制虚假的零值。账号或设备范围会应用于实时健康数据；历史趋势仅按网络汇总，并在页面明确标注。查看同期网络趋势时，原账号、设备和连接方向保留在 URL 中，返回其他排障视图可继续使用；选中的小时也写入 URL，不冒充设备级历史指标。

### 刷新和排障导航

管理台侧栏底部的「控制台偏好」集中提供自动刷新、主题、语言和表格密度。主题支持跟随系统、浅色和深色，系统外观变化及同源标签页的主题选择会同步；浏览器禁止本地存储时仍可在当前页面切换。侧栏提供全局刷新，移动端顶部也可刷新，各数据区域提供局部刷新；关闭自动刷新后明确显示上次读取的快照及时间，侧栏不继续声称实时健康。资源列表、账号详情、关系、连接与健康页面显示最后成功更新时间；概览的连接提醒、资源快照、最近账号分别报告加载结果和时间。连接状态条仅使用主连接查询的成功时间，低频网络目录的加载状态单独显示，不拖旧主数据时间。观测上报时间与请求成功时间分开呈现；离线或后台刷新失败时保留已有快照并明确标注，缓存中的在线或新鲜标记不代表此刻仍可确认的状态。普通轮询的时间变化不反复触发读屏播报。网络和房间分别加载，单个页签失败不会阻止另一页签使用。

设备可跳到所属账号、资源关系与关联连接，账号和网络也提供连接入口。搜索、作用域、页码、视图与连接详情方向保存在页面 URL 中，支持刷新、浏览器返回和分享定位；URL 不包含管理员令牌。资源与排障之间的返回入口保留来源页面的筛选和位置，共享网络下钻保留当前账号范围。游标页的向前记录和资源页签各自的筛选保留在有界的浏览器历史状态中；点击当前页签不清空筛选，键盘方向键只移动焦点，Enter 或空格才切换。分享的独立深链若无历史记录，则提供返回首页入口；游标失效可在保留筛选的情况下重新从首页加载。网络关系深链通过 `GET /admin/api/v1/topology?network_id=…` 独立读取所选网络，不依赖全局账号首批是否已加载；不存在、请求失败和预算造成的不完整分别提示。

连接工作区列出「保留但未应用的筛选」，说明当前视图的实际统计范围，并允许清除这些筛选。若所选方向被当前筛选或图展示上限排除，可选择「仅查看此方向（清除其他筛选）」：页面明确切换到对应网络和设备方向，查询最多一条真实观测，持续显示可清除的方向范围。没有观测时说明数据缺失，不推断路径或补画连接。调整趋势窗口保留选中小时，切换网络时才清除该小时定位。

连接详情使用原生模态对话框，支持 Escape 关闭、焦点限制在详情内以及关闭后的焦点恢复；拓扑边支持 Enter 或空格打开详情。桌面侧栏可收起；移动端使用遮罩导航，支持 Escape、焦点限制与关闭后返回触发按钮，设备一跳视图可更换或清除定位。资源关系的同页下钻先返回原搜索和分页索引，再沿外层来源返回。账号选择器关闭后释放查询观察者，取消无其他观察者使用的在途请求；重新打开会刷新列表，读取失败或离线时明确标注缓存。选择器按可见视口定位并可整体滚动，适应矮视口和屏幕键盘。

资源关系节点支持 Enter 或空格打开同一资源详情。资源关系与连接拓扑全屏时，焦点限制在当前图内，退出后回到触发按钮；在全屏上打开连接详情时，Escape 先关闭详情，再关闭全屏。

连接拓扑全屏保留首次筛选请求的加载、离线、错误和空结果状态，退出按钮始终可用；查询切换不会自行退出全屏。没有 committed path 的方向仍通过可展开的「无路径观测」清单打开详情，不生成虚构的路径边。

表格提供标准和紧凑密度，密度只改变行距，不缩小文字。设备主表优先显示名称与版本、在线状态、账号、网络、虚拟 IP 和最后活动；完整 ID、NAT 与 Relay RTT 保留在可展开的「技术信息」中。资源标识和地址可按需复制，剪贴板不可用时显示可手动选择的原始值；无匹配结果时提供清除筛选入口，账号详情中的固定账号范围仍保留。「导出已加载记录」仅下载当前已加载数据，最多 1000 条，JSON 包含筛选范围、导出时间、可用的快照时间、已加载数量、已导出数量、报告总数、完整性和截断标记，不作为全量一致性导出。登录令牌默认隐藏，可手动显示或隐藏。

管理台与 Control 使用同一 origin，不需要额外 CORS 放行。公网访问必须继续经过可信 HTTPS 反向代理；浏览器中的管理员令牌按敏感凭据处理，用完后退出管理台并关闭共享终端中的会话。

## 日志与证书

    sudo p2wlan-server logs --service control
    sudo p2wlan-server logs --service relay

日志轮转、访问权限和保留期限由部署者配置。证书续期必须更新实际挂载文件并重载或重启 Relay，再用 TLS 客户端验证证书链和 endpoint；ACME 客户端报告成功不等于 Relay 已加载新证书。

支持包上传失败时，先运行 `doctor --service control`。缺少 `LOG_UPLOAD_DIR`、相对路径、目录不可访问、只读文件系统或目录未保持服务账户私有权限会报告失败，即使 `/health` 返回 200。doctor 不修改自定义目录、不打印配置内容，也不代替运行中服务的 systemd/Docker 挂载检查、磁盘配额检查或实际授权上传；不要用放宽整个数据目录权限的方式绕过失败。

密钥轮换分别处理 JWT、管理控制台令牌、Relay 票据签名 key、撤权 feed token 和 TLS 私钥。只有实现明确支持重叠验证时，才可承诺无中断轮换。

## 数据保护

数据库、配置、日志和 support bundle 都可能含有敏感数据。限制目录权限，备份与生产数据分离，保留恢复演练结果在 PR/Issue 或内部运维系统，不复制到公共 docs。
