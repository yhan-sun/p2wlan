import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { ArrowUpRight, ChevronLeft, CircleAlert, MonitorSmartphone, Network, RadioTower, Search } from 'lucide-react'
import { lazy, useEffect, useMemo, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { AccountScopePicker } from '../../AccountScopePicker'
import { AsyncView } from '../../AsyncView'
import { CopyValue } from '../../CopyValue'
import { SnapshotExport } from '../../SnapshotExport'
import { ApiError, adminApi } from '../../api'
import { getLocale, tr } from '../../i18n'
import { connectionLink, readRelationshipIndexReturn, readResourceReturn, relationshipDetailNavigation, resourceOriginState, usePageState } from '../../pageState'
import { QueryStatus, useAutoRefresh } from '../../refresh'
import { AccountMark, ErrorBlock, Pagination, Panel, PendingBlock, ResourceEmptyState, ResourceReturnLink, Status, useDebouncedValue } from '../../shared/console'
import type { AdminTopology } from '../../types'
import { summarizeNetworks, topologyForNetwork, type NetworkSummary } from './relationships'
import { mergeTopologySnapshots, nextTopologySnapshotCursor } from './topologySnapshots'
const TopologyCanvas = lazy(() => import('./TopologyCanvas').then((module) => ({ default: module.TopologyCanvas })))

function NetworkOverview({ data, search, onSelect, incomplete = false, summaryOnly = false, onClear }: {
  onClear?: () => void
  incomplete?: boolean
  summaryOnly?: boolean
  data: AdminTopology
  search: string
  onSelect: (networkId: string) => void
}) {
  const normalizedSearch = search.trim().toLowerCase()
  const networks = summarizeNetworks(data).filter((item) => !normalizedSearch || item.searchText.includes(normalizedSearch))
  return <section className="network-overview">
    <header className="network-overview-heading">
      <div><span className="section-kicker">{tr("NETWORKS")}</span><h3>{tr("资源总览")}</h3><p>{tr("选择网络或个人设备分组，查看成员和设备关系。")}</p></div>
      <span className="network-total">{networks.length} {tr("个资源分组")}</span>
    </header>
    {networks.length > 0 ? <div className="network-overview-grid">
      {networks.map((item) => <button type="button" className="network-overview-card" key={item.id} onClick={() => onSelect(item.id)}>
        <span className={`network-overview-icon ${item.node.kind === 'room' ? 'room' : ''}`}>{item.node.kind === 'room' ? <RadioTower size={19} /> : <Network size={19} />}</span>
        <span className="network-overview-copy"><span className="network-kind-label">{tr(item.personal ? '个人设备' : item.node.kind === 'room' ? '房间网络' : '普通网络')}</span><strong>{item.node.label}</strong><span className="network-cidr">{tr(item.personal ? '仅属于此账号' : item.node.cidr || '未配置网段')}</span></span>
        <span className="network-overview-stats">{summaryOnly ? <span>{tr("设备详情按需加载")}</span> : <><strong>{item.onlineCount}<i>{tr("/")}{item.deviceCount}</i></strong><span>{tr(item.deviceCount === 1 ? 'device online' : 'devices online')}</span></>}</span>
        <span className="network-overview-footer"><span>{incomplete ? tr("已加载成员：") : ""}{item.memberCount} {tr(getLocale() === 'en-US' ? item.memberCount === 1 ? 'member' : 'members' : '位成员')}{item.owner ? ` · ${tr('所有者')} ${item.owner}` : ''}</span><span className="network-open-label">{tr("查看关系 ")}<ArrowUpRight size={14} /></span></span>
      </button>)}
    </div> : <div className="network-overview-empty"><Search size={18} /><strong>{tr(incomplete ? "已加载资源中没有匹配项" : "没有匹配的资源分组")}</strong><span>{tr(incomplete ? "继续加载账号，或选择账号范围后搜索。" : "试试网络、账号或设备名称。")}</span>{onClear && <button type="button" className="button secondary compact" onClick={onClear}>{tr('清除筛选')}</button>}</div>}
  </section>
}

function useMediaQuery(queryText: string) {
  const [matches, setMatches] = useState(() => typeof window !== 'undefined' && window.matchMedia(queryText).matches)
  useEffect(() => {
    const query = window.matchMedia(queryText)
    const update = () => setMatches(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [queryText])
  return matches
}

function NetworkRelationship({ data, summary, onBack, backLabel = '所有资源', accountId, search = '' }: {
  backLabel?: string
  accountId?: string
  data: AdminTopology
  summary: NetworkSummary
  onBack: () => void
  search?: string
}) {
  const location = useLocation()
  const connectionAccountId = summary.personal ? summary.node.account_id || summary.node.id.replace(/^account:/, '') : accountId
  const scopedData = useMemo(() => topologyForNetwork(data, summary.node), [data, summary.node])
  const narrow = useMediaQuery('(max-width: 650px)')
  // An explicit view choice is shareable and survives background refreshes.
  const { params, update } = usePageState()
  const chosenView = params.get('relationship_view')
  const view = chosenView === 'overview' || chosenView === 'graph' ? chosenView : !narrow && summary.memberCount + summary.deviceCount <= 8 ? 'graph' : 'overview'
  const setView = (value: string) => update({ relationship_view: value })
  const normalizedSearch = search.trim().toLowerCase()
  const members = scopedData.nodes.filter((node) => node.kind === 'account' && (!normalizedSearch || node.label.toLowerCase().includes(normalizedSearch))).sort((a, b) => a.label.localeCompare(b.label))
  const devices = scopedData.nodes.filter((node) => node.kind === 'device' && (!normalizedSearch || [node.label, node.username, node.virtual_ip, node.platform].filter(Boolean).some((value) => String(value).toLowerCase().includes(normalizedSearch)))).sort((a, b) => a.label.localeCompare(b.label))
  const onlineDevices = devices.filter((device) => device.online).length
  const membershipRoles = new Map(scopedData.edges.filter((edge) => edge.kind === 'membership').map((edge) => [edge.source, edge.role]))
  return <>
    <div className="network-graph-heading">
      <button className="button secondary compact" onClick={onBack}><ChevronLeft size={15} />{tr(backLabel)}</button>
      <CopyValue compact value={summary.id} label="复制资源 ID" /><div><strong>{summary.node.label}{summary.personal ? ` · ${tr('个人设备')}` : ''}</strong><span>{summary.memberCount} {tr("位成员 · ")}{summary.onlineCount}{tr("/")}{summary.deviceCount} {tr("台设备在线")}</span></div>
      <Link state={resourceOriginState(location)} className="button secondary compact" to={connectionLink(summary.personal ? { accountId: summary.node.account_id || summary.node.id.replace(/^account:/, ''), networkId: 'default' } : { networkId: summary.id, accountId })}>{tr('查看连接')}</Link>
      <div className="network-view-tabs" role="group" aria-label={tr("网络关系视图")}>
        <button aria-pressed={view === 'overview'} className={view === 'overview' ? 'active' : ''} onClick={() => setView('overview')}>{tr("资源概览")}</button>
        <button aria-pressed={view === 'graph'} className={view === 'graph' ? 'active' : ''} onClick={() => setView('graph')}>{tr("关系图")}</button>
      </div>
    </div>
    {view === 'graph' ? <AsyncView><TopologyCanvas data={scopedData} search={search} accountId={connectionAccountId} networkId={summary.personal ? 'default' : summary.id} /></AsyncView> : <div className="network-resource-grid">
      <section className="network-resource-panel">
        <header><div><h3>{tr("成员")}</h3><span>{tr("此网络中的账号成员")}</span></div><b>{members.length}</b></header>
        <div className="network-resource-list">
          {members.map((member) => <div className="network-resource-row" key={member.id}>
            <AccountMark account={{ id: member.account_id || member.id, username: member.username || member.label }} size="small" />
            <div className="network-resource-copy"><Link state={resourceOriginState(location)} to={`/accounts/${encodeURIComponent(member.account_id || member.id.replace(/^account:/, ''))}`}>{member.label}</Link><span>{tr((summary.personal || membershipRoles.get(member.id) === 'owner') ? '网络所有者' : '账号成员')}</span></div>
            <span className={`network-role ${(summary.personal || membershipRoles.get(member.id) === 'owner') ? 'owner' : ''}`}>{tr((summary.personal || membershipRoles.get(member.id) === 'owner') ? '所有者' : '成员')}</span>
          </div>)}
          {members.length === 0 && <div className="network-resource-empty">{tr(normalizedSearch ? '没有匹配的成员' : '暂无成员数据')}</div>}
        </div>
      </section>
      <section className="network-resource-panel">
        <header><div><h3>{tr("设备")}</h3><span>{summary.node.cidr || tr('网络设备')}</span></div><b>{onlineDevices}/{devices.length} {tr("在线")}</b></header>
        <div className="network-resource-list">
          {devices.map((device) => <div className="network-resource-row" key={device.id}>
            <span className="network-device-icon"><MonitorSmartphone size={17} /></span>
            <div className="network-resource-copy"><Link state={resourceOriginState(location)} to={connectionLink({ deviceId: device.id.replace(/^device:/, ''), accountId: connectionAccountId, networkId: summary.personal ? 'default' : summary.id })}>{device.label}</Link><span>{[device.username, device.virtual_ip, device.platform].filter(Boolean).join(' · ') || tr('设备信息未上报')}</span></div>
            <Status online={Boolean(device.online)} />
          </div>)}
          {devices.length === 0 && <div className="network-resource-empty">{tr(normalizedSearch ? '没有匹配的设备' : '暂无设备数据')}</div>}
        </div>
      </section>
    </div>}
  </>
}

export function RelationshipsPage({ accountScope }: { accountScope?: { id: string; username: string } }) {
  const refreshInterval = useAutoRefresh()
  const location = useLocation()
  const navigate = useNavigate()
  const origin = readRelationshipIndexReturn(location) || (accountScope ? null : readResourceReturn(location.state))
  const { params, update } = usePageState()
  const accountId = accountScope?.id || params.get('account_id') || ''
  const selectedNetworkId = params.get('network_id') || ''
  const search = params.get('q') || ''
  const detailSearch = params.get('resource_q') || ''
  useEffect(() => { window.scrollTo(0, 0) }, [accountId, selectedNetworkId])
  const debounced = useDebouncedValue(search)
  const rawPage = Number(params.get('relationship_page'))
  const offset = Number.isSafeInteger(rawPage) && rawPage > 0 && rawPage <= 100_000 ? rawPage * 25 : 0
  const setSelectedNetworkId = (networkId: string) => {
    if (!networkId) { update({ network_id: '', resource_q: '' }); return }
    const next = relationshipDetailNavigation(location, networkId)
    if (next) navigate({ pathname: location.pathname, search: next.search }, { state: next.state })
  }
  const backToResources = () => origin ? navigate(origin.to, { state: origin.state }) : setSelectedNetworkId('')
  const account = accountScope || (accountId ? { id: accountId, username: params.get('account_name') || accountId } : null)
  // A deep link is a separate, bounded query. Index pages are not evidence that a resource is absent.
  const selected = useQuery({ queryKey: ['relationships', 'network', selectedNetworkId], queryFn: ({ signal }) => adminApi.topologyNetwork(selectedNetworkId, 600, signal), enabled: Boolean(selectedNetworkId), refetchInterval: refreshInterval })
  const accountNetworks = useQuery({ queryKey: ['relationships', 'account-index', accountId, debounced, offset], queryFn: ({ signal }) => adminApi.networksPage({ accountId, query: debounced }, 25, offset, signal), enabled: Boolean(accountId) && !selectedNetworkId && search === debounced, refetchInterval: refreshInterval })
  const topologyView = params.get('topology_view') === 'full' ? 'full' : 'summary'
  const globalTopology = useInfiniteQuery({
    queryKey: ['relationships', 'snapshot', topologyView, accountId, selectedNetworkId], queryFn: ({ pageParam, signal }) => adminApi.topologySnapshot('', topologyView, pageParam, 100, signal), initialPageParam: '',
    getNextPageParam: nextTopologySnapshotCursor,
    enabled: !accountId && !selectedNetworkId, staleTime: 60_000, refetchOnWindowFocus: false,
  })
  const globalData = useMemo(() => mergeTopologySnapshots(globalTopology.data?.pages ?? []), [globalTopology.data?.pages])
  const selectedNetwork = useMemo(() => summarizeNetworks(selected.data).find((network) => network.id === selectedNetworkId), [selected.data, selectedNetworkId])
  const active = selectedNetworkId ? selected : accountId ? accountNetworks : globalTopology
  const total = accountNetworks.data?.total
  useEffect(() => {
    if (!selectedNetworkId && accountId && search === debounced && accountNetworks.isSuccess && total !== undefined && offset > 0 && offset >= total) update({ relationship_page: String(Math.max(0, Math.ceil(total / 25) - 1)) }, true)
  }, [total, offset, selectedNetworkId, accountId, search, debounced, accountNetworks.isSuccess])
  const partialIndex = Boolean(globalData?.partial || globalTopology.hasNextPage)
  const notFound = selected.error instanceof ApiError && selected.error.status === 404
  return <div className="page-stack topology-page-stack">
    {!accountScope && !selectedNetworkId && <ResourceReturnLink />}
    <div className="page-intro topology-toolbar"><div><h2>{selectedNetwork?.node.label || tr(accountId ? '账号资源关系' : '资源关系')}</h2><p>{tr(selectedNetworkId ? '按资源 ID 独立读取成员和设备，不受列表加载范围限制。' : accountId ? '先选择网络或个人设备分组，再加载该分组的关系。' : '搜索仅针对已加载资源；选择账号可查看其全部网络。')}</p></div><div className="toolbar-controls topology-toolbar-controls">
      <div className="search-field"><Search size={16} /><input value={selectedNetworkId ? detailSearch : search} onChange={(event) => update(selectedNetworkId ? { resource_q: event.target.value } : { q: event.target.value, relationship_page: '' }, true)} placeholder={tr(selectedNetworkId ? '搜索成员、设备或 IP' : accountId ? '搜索名称、ID、网段或房间码' : '搜索已加载的资源')} aria-label={tr(selectedNetworkId ? '搜索成员、设备或 IP' : accountId ? '搜索名称、ID、网段或房间码' : '搜索已加载的资源')} /></div>
      {(selectedNetworkId ? detailSearch : search) && <button type="button" className="button secondary compact" onClick={() => update(selectedNetworkId ? { resource_q: '' } : { q: '', relationship_page: '' })}>{tr('清除筛选')}</button>}
      {!accountId && !selectedNetworkId && <select className="select-field" aria-label={tr('关系数据范围')} value={topologyView} onChange={(event) => update({ topology_view: event.target.value })}><option value="summary">{tr('账号与网络')}</option><option value="full">{tr('包含设备与信令')}</option></select>}
      {!accountScope && <AccountScopePicker value={account} onChange={(next) => update({ account_id: next?.id || '', account_name: next?.username || '', network_id: '', resource_q: '', relationship_page: '' })} />}
    </div></div>
    <QueryStatus queries={[active]} refreshMode={!accountId && !selectedNetworkId ? 'manual' : 'automatic'} />
    <Panel className="topology-main-panel">
      <div className="truth-notice topology-truth"><CircleAlert size={15} /><span>{tr('连线表示成员关系和设备挂载。实时 Direct / Relay 路径请到「连接排障」查看。')}</span></div>
      {selectedNetworkId ? <>
        {!selectedNetwork && <div className="network-graph-heading"><button className="button secondary compact" onClick={backToResources}><ChevronLeft size={15} />{tr(origin?.label || '所有资源')}</button><code>{selectedNetworkId}</code></div>}
        {selected.isPending ? <PendingBlock queries={[selected]} label="正在读取网络关系…" /> : selected.error && !selected.data ? <>
          {notFound ? <div className="network-overview-empty" role="status"><strong>{tr('所选资源不存在')}</strong><span>{tr('资源可能已删除，请返回列表重新选择。')}</span></div> : <ErrorBlock error={selected.error} onRetry={() => { void selected.refetch() }} />}
        </> : selected.data && selectedNetwork ? <>
          {selected.data.partial && <p className="query-status" role="status">{tr('该资源超过单次展示预算，当前为部分关系数据；这不表示资源不存在。')}</p>}
          <NetworkRelationship key={selectedNetworkId} data={selected.data} summary={selectedNetwork} accountId={accountId} onBack={backToResources} backLabel={origin?.label} search={detailSearch} />
          <SnapshotExport items={[{ nodes: selected.data.nodes, edges: selected.data.edges }]} filename="resource-relationships" generatedAt={selected.data.generated_at} scope={{ network_id: selectedNetworkId, partial: selected.data.partial, loaded_nodes: selected.data.nodes.length, loaded_edges: selected.data.edges.length }} complete={!selected.data.partial} />
        </> : <ErrorBlock error={new Error('已收到资源快照，但缺少资源根节点。请重试。')} onRetry={() => { void selected.refetch() }} />}
      </> : accountId ? <>
        <div className="network-graph-heading"><button className="button secondary compact" onClick={() => setSelectedNetworkId(`personal:${accountId}`)}><MonitorSmartphone size={15} />{tr('查看个人设备')}</button><span>{tr('共享网络按账号成员关系分页列出。')}</span></div>
        {accountNetworks.isPending || search !== debounced ? <PendingBlock queries={[accountNetworks]} /> : accountNetworks.error && !accountNetworks.data ? <ErrorBlock error={accountNetworks.error} onRetry={() => { void accountNetworks.refetch() }} /> : accountNetworks.data && <>
          <div className="network-overview-grid">{accountNetworks.data.items.map((network) => <button key={network.id} type="button" className="network-overview-card" onClick={() => setSelectedNetworkId(network.id)}>
            <span className="network-overview-icon"><Network size={19} /></span><span className="network-overview-copy"><span className="network-kind-label">{tr(network.is_room ? '房间网络' : '普通网络')}</span><strong>{network.name}</strong><span className="network-cidr">{network.cidr}</span></span><span className="network-overview-stats"><strong>{network.online_devices}/{network.device_count}</strong><span>{tr('设备在线')}</span></span><span className="network-overview-footer">{network.member_count} {tr('位成员')}<span className="network-open-label">{tr('查看关系')}<ArrowUpRight size={14} /></span></span>
          </button>)}</div>
          {!accountNetworks.data.items.length && <ResourceEmptyState message={search ? '没有匹配的资源分组' : '该账号暂无共享网络，可查看个人设备。'} onClear={search ? () => update({ q: '', relationship_page: '' }) : undefined} />}
          <Pagination total={accountNetworks.data.total} offset={offset} limit={25} onChange={(value) => update({ relationship_page: value ? String(value / 25) : '' })} />
        </>}
      </> : <>
        {globalData && <div className="topology-page-progress"><span>{tr('已加载 ')}{globalData.nodes.length} {tr('个资源')} · {globalData.edges.length} {tr('条关系')}</span>
          {globalData.partial ? <span className="topology-partial-warning">{tr('当前只显示部分资源，请选择具体账号查看详情。')}</span> : globalTopology.hasNextPage ? <button className="button secondary compact" onClick={() => { void globalTopology.fetchNextPage() }} disabled={globalTopology.isFetchingNextPage}>{tr(globalTopology.isFetchingNextPage ? '加载中…' : '加载更多关系')}</button> : <span>{tr('关系快照已加载完成')}</span>}
        </div>}
        {globalTopology.isPending ? <PendingBlock queries={[globalTopology]} label="正在读取网络关系…" /> : globalTopology.error && !globalData ? <ErrorBlock error={globalTopology.error} onRetry={() => { void globalTopology.refetch() }} /> : globalData && <NetworkOverview summaryOnly={topologyView === 'summary'} data={globalData} search={search} onSelect={setSelectedNetworkId} incomplete={partialIndex} onClear={search ? () => update({ q: '' }) : undefined} />}
      </>}
    </Panel>
  </div>
}
