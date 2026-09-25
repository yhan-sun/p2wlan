import { useMemo, useState } from 'react'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { CircleAlert, Search } from 'lucide-react'
import { adminApi } from '../../api'
import { PageHeader, Panel, StatusPill } from '../../components/ui/console'
import { TopologyCanvas } from './TopologyCanvas'
import { mergeTopologyPages } from '../../topologyPaging'

export function RelationshipsPage() {
  const [accountId, setAccountId] = useState('')
  const [search, setSearch] = useState('')
  const accounts = useQuery({
    queryKey: ['accounts', 'relationship-scope'],
    queryFn: () => adminApi.accounts('', 50, 0),
  })
  const accountTopology = useQuery({
    queryKey: ['relationships', 'account', accountId],
    queryFn: () => adminApi.topology(accountId),
    enabled: Boolean(accountId),
  })
  const globalTopology = useInfiniteQuery({
    queryKey: ['relationships', 'global-paged'],
    queryFn: ({ pageParam }) => adminApi.topologyPage(pageParam, 12, 600),
    initialPageParam: '',
    getNextPageParam: (lastPage) => lastPage.partial ? undefined : (lastPage.next_cursor || undefined),
    enabled: !accountId,
  })
  const globalData = useMemo(
    () => mergeTopologyPages(globalTopology.data?.pages ?? []),
    [globalTopology.data?.pages],
  )
  const relationshipData = accountId ? accountTopology.data : globalData
  const relationshipPending = accountId ? accountTopology.isPending : globalTopology.isPending
  const relationshipError = accountId ? accountTopology.error : globalTopology.error

  return <div className="page-stack topology-page-stack">
    <PageHeader
      eyebrow="资源关系"
      title={accountId ? '账号资源关系' : '全局资源关系'}
      description={accountId ? '账号、共享网络 / 房间与设备之间的控制面关系。' : '控制面资源关系，不是 Direct / Relay 数据路径；大规模部署按账号分批加载。'}
      actions={<div className="toolbar-controls">
        <label className="search-field"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索账号、设备、IP、网络" aria-label="搜索资源关系" /></label>
        <select className="select-field" value={accountId} onChange={(event) => setAccountId(event.target.value)} aria-label="按账号过滤"><option value="">全部账号</option>{accounts.data?.items.map((account) => <option value={account.id} key={account.id}>{account.username}</option>)}</select>
      </div>}
    />
    <Panel className="topology-main-panel">
      <div className="truth-notice topology-truth"><CircleAlert size={15} /><span>连线表示成员关系与设备挂载；待处理信令默认隐藏。Direct / Relay 数据路径请到连接路径查看。</span></div>
      {!accountId && globalData && <div className="topology-page-progress">
        <span>已加载 {globalData.loaded_accounts} / {globalData.total_accounts} 个账号</span>
        {globalData.partial
          ? <span className="topology-partial-warning">当前切片达到 {globalData.partial_reason === 'edge_budget' ? '边' : '节点'}预算；请选择具体账号继续下钻。</span>
          : globalTopology.hasNextPage
            ? <button className="button secondary compact" onClick={() => globalTopology.fetchNextPage()} disabled={globalTopology.isFetchingNextPage}>{globalTopology.isFetchingNextPage ? '加载中…' : '加载更多账号'}</button>
            : <StatusPill tone="success" dot>全局账号已加载完成</StatusPill>}
      </div>}
      <TopologyCanvas data={relationshipData} loading={relationshipPending} error={relationshipError instanceof Error ? relationshipError.message : undefined} search={search} />
    </Panel>
  </div>
}
