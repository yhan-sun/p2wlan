import {
  type FormEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useState,
} from 'react'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock3,
  KeyRound,
  LayoutDashboard,
  LogOut,
  MonitorSmartphone,
  Network,
  RadioTower,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Users,
  Waypoints,
} from 'lucide-react'
import {
  BrowserRouter,
  Link,
  NavLink,
  Navigate,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from 'react-router-dom'
import { adminApi, ApiError, clearAdminToken, getAdminToken, setAdminToken, verifyAdminToken } from './api'
import { accountColor, colorWithAlpha } from './colors'
import { TopologyCanvas } from './TopologyCanvas'
import type {
  AdminAccount,
  AdminDevice,
  AdminNetwork,
  AdminRoom,
  AdminTopology,
} from './types'

const PAGE_SIZE = 25

function formatAgo(unix?: number): string {
  if (!unix) return '从未'
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unix)
  if (seconds < 45) return '刚刚'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)} 天前`
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', year: 'numeric' }).format(new Date(unix * 1000))
}

function formatDate(unix?: number): string {
  if (!unix) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
  }).format(new Date(unix * 1000))
}

function formatDuration(seconds?: number): string {
  let value = Math.max(0, seconds ?? 0)
  const days = Math.floor(value / 86400)
  value %= 86400
  const hours = Math.floor(value / 3600)
  value %= 3600
  const minutes = Math.floor(value / 60)
  if (days) return `${days} 天 ${hours} 小时`
  if (hours) return `${hours} 小时 ${minutes} 分钟`
  return `${minutes} 分钟`
}

function natLabel(value: string): string {
  if (!value || value.toLowerCase() === 'unknown') return 'Unknown'
  const match = value.match(/(?:^|;)m=([^;]+)/i)
  return (match?.[1] ?? value).replaceAll('_', ' ')
}

function useDebouncedValue<T>(value: T, delay = 250): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(timer)
  }, [value, delay])
  return debounced
}

function AccountMark({ account, size = 'normal' }: { account: Pick<AdminAccount, 'id' | 'username'>; size?: 'normal' | 'small' | 'large' }) {
  const color = accountColor(account.id)
  const initials = (account.username || '?').trim().slice(0, 2).toUpperCase()
  return <span className={`account-mark ${size}`} style={{ color, background: colorWithAlpha(color, 0.12), borderColor: colorWithAlpha(color, 0.22) }}>{initials}</span>
}

function Status({ online }: { online: boolean }) {
  return <span className={`status-label ${online ? 'online' : ''}`}><span />{online ? '在线' : '离线'}</span>
}

function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return <div className="loading-block"><div className="spinner" />{label}</div>
}

function ErrorBlock({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : '加载失败'
  return <div className="error-block"><CircleAlert size={18} /><div><strong>无法加载数据</strong><span>{message}</span></div></div>
}

// A paused query (the browser is offline) is neither loading nor failed:
// react-query keeps isPending true while isFetching is false, so gating a page
// on isLoading would render nothing at all, with no message and no retry hint.
function PendingBlock({ queries, label = '加载中…' }: { queries: { fetchStatus: string }[]; label?: string }) {
  if (queries.some((query) => query.fetchStatus === 'paused')) {
    return <ErrorBlock error={new Error('浏览器当前离线，无法访问 Control。恢复网络后会自动重新请求。')} />
  }
  return <LoadingBlock label={label} />
}

// Control owns whether a live Direct/Relay path is observable at all. Render the
// control plane's own statement, and only fall back to the localized
// explanation while the control plane confirms the path is not observable —
// otherwise the console would keep asserting something it no longer knows.
function PathNotice({ data, fallback }: { data?: AdminTopology; fallback: string }) {
  const note = data?.path_observation_available ? data.path_observation_note : ''
  return <div className="truth-notice"><CircleAlert size={15} /><span>{note || fallback}</span></div>
}

function MetricCard({ icon, label, value, meta }: { icon: ReactNode; label: string; value: ReactNode; meta: ReactNode }) {
  return <article className="metric-card-v2">
    <div className="metric-icon">{icon}</div>
    <div className="metric-copy"><span>{label}</span><strong>{value}</strong><p>{meta}</p></div>
  </article>
}

function Panel({ title, subtitle, action, className = '', children }: { title?: string; subtitle?: string; action?: ReactNode; className?: string; children: ReactNode }) {
  return <section className={`panel-v2 ${className}`}>
    {(title || action) && <header className="panel-v2-header">
      <div>{title && <h2>{title}</h2>}{subtitle && <p>{subtitle}</p>}</div>
      {action}
    </header>}
    {children}
  </section>
}

function DataTable<T>({ columns, data, onRowClick, empty = '暂无数据' }: {
  columns: ColumnDef<T, unknown>[]
  data: T[]
  onRowClick?: (row: T) => void
  empty?: string
}) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() })
  return <div className="data-table-wrap"><table className="data-table">
    <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => <th key={header.id}>{header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}</th>)}</tr>)}</thead>
    <tbody>
      {table.getRowModel().rows.map((row) => <tr key={row.id} className={onRowClick ? 'clickable' : ''} onClick={() => onRowClick?.(row.original)}>{row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}
      {data.length === 0 && <tr><td className="table-empty" colSpan={columns.length}>{empty}</td></tr>}
    </tbody>
  </table></div>
}

function Pagination({ total, offset, limit, onChange }: { total: number; offset: number; limit: number; onChange: (offset: number) => void }) {
  const start = total === 0 ? 0 : offset + 1
  const end = Math.min(total, offset + limit)
  return <div className="pagination-v2"><span>{start}–{end} / {total}</span><div>
    <button className="button secondary compact" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}><ChevronLeft size={15} />上一页</button>
    <button className="button secondary compact" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>下一页<ChevronRight size={15} /></button>
  </div></div>
}

function Login({ onSuccess }: { onSuccess: () => void }) {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    const normalized = token.trim()
    if (normalized.length < 32) {
      setError('管理员令牌至少需要 32 个字符。')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      await verifyAdminToken(normalized)
      setAdminToken(normalized)
      onSuccess()
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) setError('管理员令牌无效。')
      else setError(reason instanceof Error ? reason.message : '无法连接到 Control。')
    } finally {
      setSubmitting(false)
    }
  }

  return <main className="login-page-v2">
    <section className="login-brand-side">
      <div className="brand-lockup large"><div className="brand-symbol"><Waypoints size={22} /></div><div><strong>P2WLAN</strong><span>Control</span></div></div>
      <div className="login-brand-copy"><span className="eyebrow-v2">SELF-HOSTED CONTROL PLANE</span><h1>看清每一个账号，<br />也看清整张网络。</h1><p>账号、设备、网络、房间和控制面拓扑统一在一个只读管理界面中。</p></div>
      <div className="login-security"><ShieldCheck size={17} /><span>管理权限与用户 JWT / 设备凭据完全隔离</span></div>
    </section>
    <section className="login-form-side">
      <form className="login-card-v2" onSubmit={submit}>
        <div className="mobile-brand"><div className="brand-symbol"><Waypoints size={20} /></div><strong>P2WLAN Control</strong></div>
        <span className="eyebrow-v2">ADMIN CONSOLE</span>
        <h2>登录控制台</h2>
        <p>输入部署时配置的 <code>CONTROL_ADMIN_TOKEN</code>。</p>
        <label htmlFor="admin-token">管理员令牌</label>
        <div className="input-with-icon"><KeyRound size={16} /><input id="admin-token" type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="至少 32 个字符" autoComplete="current-password" autoFocus /></div>
        <div className={`login-error ${error ? 'visible' : ''}`}>{error || ' '}</div>
        <button className="button primary login-button" type="submit" disabled={submitting}>{submitting ? <><div className="spinner light" />验证中…</> : <>进入控制台<ArrowRight size={16} /></>}</button>
        <div className="session-note"><CircleCheck size={14} />令牌仅保存在当前标签页会话中</div>
      </form>
    </section>
  </main>
}

const navGroups = [
  { label: 'GENERAL', items: [
    { to: '/', end: true, icon: <LayoutDashboard size={17} />, label: '概览' },
    { to: '/accounts', icon: <Users size={17} />, label: '账号' },
    { to: '/topology', icon: <Waypoints size={17} />, label: '拓扑' },
  ] },
  { label: 'NETWORK', items: [
    { to: '/devices', icon: <MonitorSmartphone size={17} />, label: '设备' },
    { to: '/networks', icon: <Network size={17} />, label: '网络与房间' },
  ] },
  { label: 'SYSTEM', items: [
    { to: '/system', icon: <Activity size={17} />, label: '运行状态' },
  ] },
]

function pageMeta(pathname: string): { title: string; eyebrow: string } {
  if (pathname.startsWith('/accounts/')) return { title: '账号详情', eyebrow: 'ACCOUNTS' }
  if (pathname === '/accounts') return { title: '账号', eyebrow: 'ACCOUNTS' }
  if (pathname === '/topology') return { title: '网络拓扑', eyebrow: 'TOPOLOGY' }
  if (pathname === '/devices') return { title: '设备', eyebrow: 'DEVICES' }
  if (pathname === '/networks') return { title: '网络与房间', eyebrow: 'NETWORK' }
  if (pathname === '/system') return { title: '运行状态', eyebrow: 'SYSTEM' }
  return { title: '概览', eyebrow: 'OVERVIEW' }
}

function Shell({ onLogout }: { onLogout: () => void }) {
  const location = useLocation()
  const meta = pageMeta(location.pathname)
  const queryClient = useQueryClient()
  const runtime = useQuery({ queryKey: ['runtime-shell'], queryFn: adminApi.runtime, refetchInterval: 60_000 })
  const [refreshing, setRefreshing] = useState(false)

  const refresh = async () => {
    setRefreshing(true)
    try { await queryClient.invalidateQueries() } finally { window.setTimeout(() => setRefreshing(false), 250) }
  }

  return <div className="app-layout">
    <aside className="sidebar-v2">
      <Link to="/" className="brand-lockup"><div className="brand-symbol"><Waypoints size={20} /></div><div><strong>P2WLAN</strong><span>Control</span></div></Link>
      <nav className="sidebar-nav">{navGroups.map((group) => <div className="nav-group" key={group.label}><span className="nav-group-label">{group.label}</span>{group.items.map((item) => <NavLink key={item.to} to={item.to} end={item.end} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>{item.icon}<span>{item.label}</span></NavLink>)}</div>)}</nav>
      <div className="sidebar-runtime">
        <div className="runtime-line"><span className={`health-dot${runtime.isError ? ' down' : runtime.isPending ? ' unknown' : ''}`} /><strong>{runtime.isError ? 'Control 不可达' : runtime.isPending ? '正在检查 Control' : 'Control healthy'}</strong></div>
        <span>{runtime.data?.build_version ?? (runtime.isError ? '—' : 'loading…')}</span>
        <small>只读管理模式</small>
      </div>
    </aside>
    <div className="app-main">
      <header className="topbar-v2">
        <div><span className="topbar-eyebrow">{meta.eyebrow}</span><h1>{meta.title}</h1></div>
        <div className="topbar-actions-v2">
          <button className="icon-button-v2" onClick={refresh} title="刷新数据" aria-label="刷新数据"><RefreshCw size={17} className={refreshing ? 'spin' : ''} /></button>
          <div className="topbar-divider" />
          <button className="user-menu-button" onClick={() => { clearAdminToken(); queryClient.clear(); onLogout() }}><span className="user-avatar">AD</span><span className="user-menu-copy"><strong>admin</strong><small>read-only</small></span><LogOut size={15} /></button>
        </div>
      </header>
      <main className="page-content"><Outlet /></main>
    </div>
  </div>
}

function Dashboard() {
  const overview = useQuery({ queryKey: ['overview'], queryFn: adminApi.overview, refetchInterval: 30_000 })
  const accounts = useQuery({ queryKey: ['accounts', 'recent'], queryFn: () => adminApi.accounts('', 6, 0), refetchInterval: 30_000 })
  const topology = useQuery({ queryKey: ['topology', 'global'], queryFn: () => adminApi.topology(), refetchInterval: 30_000 })
  const runtime = useQuery({ queryKey: ['runtime'], queryFn: adminApi.runtime, refetchInterval: 30_000 })
  if (overview.isPending || accounts.isPending || topology.isPending || runtime.isPending) return <PendingBlock queries={[overview, accounts, topology, runtime]} label="正在读取 Control 状态…" />
  const error = overview.error || accounts.error || topology.error || runtime.error
  if (error) return <ErrorBlock error={error} />
  if (!overview.data || !accounts.data || !topology.data || !runtime.data) return <ErrorBlock error={new Error('Control 未返回完整快照，请刷新重试。')} />

  return <div className="page-stack">
    <section className="metrics-grid-v2">
      <MetricCard icon={<Users size={18} />} label="账号" value={overview.data.users} meta="Control 中的非系统账号" />
      <MetricCard icon={<MonitorSmartphone size={18} />} label="设备" value={overview.data.devices} meta={<><span className="positive-text">{overview.data.online_devices} 在线</span> · {overview.data.devices - overview.data.online_devices} 离线</>} />
      <MetricCard icon={<Network size={18} />} label="网络" value={overview.data.networks} meta={`${overview.data.rooms} 个房间网络`} />
      <MetricCard icon={<Activity size={18} />} label="控制面" value={overview.data.pending_signals} meta={`${overview.data.active_tunnels} 个活动隧道 · 待处理信令`} />
    </section>

    <section className="dashboard-grid">
      <Panel className="dashboard-topology" title="全局拓扑" subtitle="账号 → 网络 / 房间 → 设备的真实 Control 关系" action={<Link className="text-link" to="/topology">打开全屏拓扑<ArrowRight size={14} /></Link>}>
        <TopologyCanvas data={topology.data} compact />
      </Panel>
      <Panel className="health-card" title="Control" subtitle="当前服务进程" action={<span className="badge success"><span />正常</span>}>
        <div className="health-runtime-big"><div className="health-runtime-icon"><Server size={22} /></div><div><span>运行时间</span><strong>{formatDuration(runtime.data.uptime_seconds)}</strong></div></div>
        <dl className="detail-list compact">
          <div><dt>版本</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>提交</dt><dd className="mono">{runtime.data.build_commit.slice(0, 10)}</dd></div>
          <div><dt>启动时间</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>权限</dt><dd>只读</dd></div>
        </dl>
      </Panel>
    </section>

    <section className="dashboard-lower-grid">
      <Panel title="最近账号" subtitle="按设备最后活动时间排序" action={<Link className="text-link" to="/accounts">全部账号<ArrowRight size={14} /></Link>}>
        <div className="recent-account-list">{accounts.data.items.map((account) => <Link className="recent-account-row" to={`/accounts/${encodeURIComponent(account.id)}`} key={account.id}>
          <AccountMark account={account} />
          <div className="recent-account-main"><strong>{account.username}</strong><span>{account.email}</span></div>
          <div className="recent-account-stat"><strong>{account.online_devices}/{account.device_count}</strong><span>在线设备</span></div>
          <div className="recent-account-stat"><strong>{account.network_count}</strong><span>网络</span></div>
          <div className="recent-account-time">{formatAgo(account.last_seen)}</div>
          <ChevronRight size={15} />
        </Link>)}</div>
      </Panel>
      <Panel title="控制面摘要" subtitle="这些计数不是数据面吞吐">
        <div className="control-summary-grid">
          <div><span className="summary-icon"><Activity size={17} /></span><strong>{overview.data.pending_signals}</strong><small>待处理信令</small></div>
          <div><span className="summary-icon"><Waypoints size={17} /></span><strong>{overview.data.active_tunnels}</strong><small>活动隧道</small></div>
          <div><span className="summary-icon"><RadioTower size={17} /></span><strong>{overview.data.rooms}</strong><small>房间</small></div>
          <div><span className="summary-icon"><Clock3 size={17} /></span><strong>{formatAgo(overview.data.generated_at)}</strong><small>快照时间</small></div>
        </div>
      </Panel>
    </section>
  </div>
}

function AccountsPage() {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [offset, setOffset] = useState(0)
  const debounced = useDebouncedValue(query)
  useEffect(() => setOffset(0), [debounced])
  const result = useQuery({ queryKey: ['accounts', debounced, offset], queryFn: () => adminApi.accounts(debounced, PAGE_SIZE, offset) })

  const columns = useMemo<ColumnDef<AdminAccount, unknown>[]>(() => [
    { id: 'account', header: '账号', cell: ({ row }) => <div className="identity-cell"><AccountMark account={row.original} /><div><strong>{row.original.username}</strong><span>{row.original.email}</span></div></div> },
    { id: 'devices', header: '设备', cell: ({ row }) => <div className="ratio-cell"><strong>{row.original.online_devices}/{row.original.device_count}</strong><span>{row.original.device_count ? Math.round(row.original.online_devices / row.original.device_count * 100) : 0}% 在线</span></div> },
    { accessorKey: 'network_count', header: '网络' },
    { accessorKey: 'room_count', header: '房间' },
    { id: 'last_seen', header: '最近活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
    { id: 'created_at', header: '注册时间', cell: ({ row }) => formatDate(row.original.created_at) },
    { id: 'action', header: '', cell: () => <ChevronRight className="row-chevron" size={16} /> },
  ], [])

  return <div className="page-stack">
    <div className="page-intro"><div><h2>所有账号</h2><p>从账号维度查看设备、网络、房间和共享拓扑。</p></div><div className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索用户名或邮箱" /></div></div>
    <Panel>
      {result.isLoading ? <LoadingBlock /> : result.error ? <ErrorBlock error={result.error} /> : result.data && <>
        <DataTable<AdminAccount> columns={columns} data={result.data.items} onRowClick={(account) => navigate(`/accounts/${encodeURIComponent(account.id)}`)} empty="没有符合条件的账号" />
        <Pagination total={result.data.total} offset={offset} limit={PAGE_SIZE} onChange={setOffset} />
      </>}
    </Panel>
  </div>
}

function DeviceTable({ devices }: { devices: AdminDevice[] }) {
  const columns = useMemo<ColumnDef<AdminDevice, unknown>[]>(() => [
    { id: 'device', header: '设备', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.device_name}</strong><span>{row.original.platform} · {row.original.app_version || '未知版本'}</span></div> },
    { accessorKey: 'network_name', header: '网络' },
    { id: 'ip', header: 'Virtual IP', cell: ({ row }) => <span className="mono">{row.original.virtual_ip}</span> },
    { id: 'nat', header: 'NAT', cell: ({ row }) => natLabel(row.original.nat_type) },
    { id: 'rtt', header: 'Relay RTT', cell: ({ row }) => row.original.relay_rtt_ms === undefined ? '—' : `${row.original.relay_rtt_ms} ms` },
    { id: 'status', header: '状态', cell: ({ row }) => <Status online={row.original.online} /> },
    { id: 'last', header: '最后活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
  ], [])
  return <DataTable<AdminDevice> columns={columns} data={devices} empty="该账号还没有设备" />
}

function NetworkTable({ networks }: { networks: AdminNetwork[] }) {
  const columns = useMemo<ColumnDef<AdminNetwork, unknown>[]>(() => [
    { id: 'name', header: '网络', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.name}</strong><span className="mono">{row.original.id}</span></div> },
    { id: 'cidr', header: 'CIDR', cell: ({ row }) => <span className="mono">{row.original.cidr}</span> },
    { accessorKey: 'owner_username', header: '所有者' },
    { accessorKey: 'member_count', header: '成员' },
    { id: 'devices', header: '设备', cell: ({ row }) => `${row.original.online_devices}/${row.original.device_count} 在线` },
    { id: 'type', header: '类型', cell: ({ row }) => <span className={`badge ${row.original.is_room ? 'purple' : ''}`}>{row.original.is_room ? '房间网络' : '普通网络'}</span> },
  ], [])
  return <DataTable<AdminNetwork> columns={columns} data={networks} empty="该账号还没有网络" />
}

function RoomTable({ rooms }: { rooms: AdminRoom[] }) {
  const columns = useMemo<ColumnDef<AdminRoom, unknown>[]>(() => [
    { id: 'name', header: '房间', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.name}</strong><span className="mono">#{row.original.code}</span></div> },
    { id: 'cidr', header: 'CIDR', cell: ({ row }) => <span className="mono">{row.original.cidr}</span> },
    { accessorKey: 'owner_username', header: '所有者' },
    { accessorKey: 'member_count', header: '成员' },
    { id: 'devices', header: '设备', cell: ({ row }) => `${row.original.online_devices}/${row.original.device_count} 在线` },
    { id: 'join', header: '加入', cell: ({ row }) => <span className={`badge ${row.original.join_locked ? 'warning' : 'success'}`}>{row.original.join_locked ? '已锁定' : '可加入'}</span> },
  ], [])
  return <DataTable<AdminRoom> columns={columns} data={rooms} empty="该账号没有加入房间" />
}

function AccountDetailPage() {
  const { id = '' } = useParams()
  const [tab, setTab] = useState<'topology' | 'devices' | 'networks' | 'rooms'>('topology')
  const detail = useQuery({ queryKey: ['account', id], queryFn: () => adminApi.account(id), enabled: Boolean(id) })
  const topology = useQuery({ queryKey: ['topology', 'account', id], queryFn: () => adminApi.topology(id), enabled: Boolean(id) })
  if (detail.isPending) return <PendingBlock queries={[detail]} label="正在加载账号…" />
  if (detail.error) return <ErrorBlock error={detail.error} />
  if (!detail.data) return <ErrorBlock error={new Error('Control 未返回该账号详情，请返回账号列表重试。')} />
  const account = detail.data.account
  const color = accountColor(account.id)

  return <div className="page-stack">
    <section className="account-hero">
      <AccountMark account={account} size="large" />
      <div className="account-hero-copy"><span className="account-color-label" style={{ color }}>ACCOUNT</span><h2>{account.username}</h2><p>{account.email}</p></div>
      <div className="account-hero-stats"><div><strong>{account.device_count}</strong><span>设备</span></div><div><strong className="positive-text">{account.online_devices}</strong><span>在线</span></div><div><strong>{account.network_count}</strong><span>网络</span></div><div><strong>{account.room_count}</strong><span>房间</span></div></div>
    </section>

    <div className="tabs-v2">
      {([['topology', '拓扑'], ['devices', `设备 ${account.device_count}`], ['networks', `网络 ${account.network_count}`], ['rooms', `房间 ${account.room_count}`]] as const).map(([value, label]) => <button key={value} className={tab === value ? 'active' : ''} onClick={() => setTab(value)}>{label}</button>)}
    </div>

    {tab === 'topology' && <Panel title={`${account.username} 的拓扑`} subtitle="包含该账号以及共享网络 / 房间中的对端账号和设备">
      <PathNotice data={topology.data} fallback="Control 当前没有持久化 daemon 的实时 Direct / Relay 业务路径，因此这里只展示成员关系、设备挂载关系和待处理信令，不伪造连接路径。" />
      <TopologyCanvas data={topology.data} loading={topology.isPending} error={topology.error instanceof Error ? topology.error.message : undefined} />
    </Panel>}
    {tab === 'devices' && <Panel><DeviceTable devices={detail.data.devices} /></Panel>}
    {tab === 'networks' && <Panel><NetworkTable networks={detail.data.networks} /></Panel>}
    {tab === 'rooms' && <Panel><RoomTable rooms={detail.data.rooms} /></Panel>}
  </div>
}

function TopologyPage() {
  const [accountId, setAccountId] = useState('')
  const [search, setSearch] = useState('')
  const accounts = useQuery({ queryKey: ['accounts', 'topology-filter'], queryFn: () => adminApi.accounts('', 200, 0) })
  const topology = useQuery({ queryKey: ['topology', accountId || 'global'], queryFn: () => adminApi.topology(accountId || undefined) })

  return <div className="page-stack topology-page-stack">
    <div className="page-intro topology-toolbar"><div><h2>{accountId ? '账号拓扑' : '全局拓扑'}</h2><p>{accountId ? '保留共享网络中的对端账号和设备。' : '所有账号、网络、房间与设备的控制面关系。'}</p></div><div className="toolbar-controls">
      <div className="search-field"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索账号、设备、IP、网络" /></div>
      <select className="select-field" value={accountId} onChange={(event) => setAccountId(event.target.value)}><option value="">全部账号</option>{accounts.data?.items.map((account) => <option value={account.id} key={account.id}>{account.username}</option>)}</select>
    </div></div>
    <Panel className="topology-main-panel">
      <div className="truth-notice topology-truth"><CircleAlert size={15} /><span>颜色用于区分账号；绿色 / 灰色状态点表示设备在线状态。虚线只表示待处理 signaling，不代表 Relay 数据路径。</span></div>
      <TopologyCanvas data={topology.data} loading={topology.isPending} error={topology.error instanceof Error ? topology.error.message : undefined} search={search} />
    </Panel>
  </div>
}

function DevicesPage() {
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const [offset, setOffset] = useState(0)
  const debounced = useDebouncedValue(query)
  useEffect(() => setOffset(0), [debounced, status])
  const result = useQuery({ queryKey: ['devices', debounced, status, offset], queryFn: () => adminApi.devices(debounced, status, PAGE_SIZE, offset) })
  const columns = useMemo<ColumnDef<AdminDevice, unknown>[]>(() => [
    { id: 'device', header: '设备', cell: ({ row }) => <div className="primary-secondary"><strong>{row.original.device_name}</strong><span>{row.original.platform} · {row.original.app_version || '未知版本'}</span></div> },
    { accessorKey: 'username', header: '账号' },
    { accessorKey: 'network_name', header: '网络' },
    { id: 'ip', header: 'Virtual IP', cell: ({ row }) => <span className="mono">{row.original.virtual_ip}</span> },
    { id: 'nat', header: 'NAT', cell: ({ row }) => natLabel(row.original.nat_type) },
    { id: 'rtt', header: 'Relay RTT', cell: ({ row }) => row.original.relay_rtt_ms === undefined ? '—' : `${row.original.relay_rtt_ms} ms` },
    { id: 'status', header: '状态', cell: ({ row }) => <Status online={row.original.online} /> },
    { id: 'last', header: '最后活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
  ], [])

  return <div className="page-stack">
    <div className="page-intro"><div><h2>设备</h2><p>全部账号下已注册的 P2WLAN 设备。</p></div><div className="toolbar-controls"><div className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索设备、账号、IP 或网络" /></div><select className="select-field" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">全部状态</option><option value="online">在线</option><option value="offline">离线</option></select></div></div>
    <Panel>{result.isPending ? <PendingBlock queries={[result]} /> : result.error ? <ErrorBlock error={result.error} /> : result.data ? <><DataTable<AdminDevice> columns={columns} data={result.data.items} /><Pagination total={result.data.total} offset={offset} limit={PAGE_SIZE} onChange={setOffset} /></> : <ErrorBlock error={new Error('Control 未返回设备列表。')} />}</Panel>
  </div>
}

function NetworksPage() {
  const [tab, setTab] = useState<'networks' | 'rooms'>('networks')
  const networks = useQuery({ queryKey: ['networks'], queryFn: () => adminApi.networks() })
  const rooms = useQuery({ queryKey: ['rooms'], queryFn: () => adminApi.rooms() })
  const error = networks.error || rooms.error
  if (networks.isPending || rooms.isPending) return <PendingBlock queries={[networks, rooms]} />
  if (error) return <ErrorBlock error={error} />
  if (!networks.data || !rooms.data) return <ErrorBlock error={new Error('Control 未返回完整的网络与房间列表。')} />
  return <div className="page-stack">
    <div className="page-intro"><div><h2>网络与房间</h2><p>统一查看普通网络与房间网络的成员和设备规模。</p></div></div>
    <div className="tabs-v2"><button className={tab === 'networks' ? 'active' : ''} onClick={() => setTab('networks')}>网络 {networks.data.total}</button><button className={tab === 'rooms' ? 'active' : ''} onClick={() => setTab('rooms')}>房间 {rooms.data.total}</button></div>
    <Panel>{tab === 'networks' ? <NetworkTable networks={networks.data.items} /> : <RoomTable rooms={rooms.data.items} />}</Panel>
  </div>
}

function SystemPage() {
  const runtime = useQuery({ queryKey: ['runtime-system'], queryFn: adminApi.runtime, refetchInterval: 15_000 })
  const overview = useQuery({ queryKey: ['overview-system'], queryFn: adminApi.overview, refetchInterval: 15_000 })
  if (runtime.isPending || overview.isPending) return <PendingBlock queries={[runtime, overview]} />
  const error = runtime.error || overview.error
  if (error) return <ErrorBlock error={error} />
  if (!runtime.data || !overview.data) return <ErrorBlock error={new Error('Control 未返回完整的运行状态快照。')} />
  return <div className="page-stack">
    <div className="page-intro"><div><h2>Control 运行状态</h2><p>只展示当前 Control 进程与数据库能直接确认的事实。</p></div><span className="badge success large"><span />运行中</span></div>
    <section className="system-grid">
      <Panel title="进程" subtitle="构建与启动信息">
        <div className="system-hero"><div className="system-hero-icon"><Server size={26} /></div><div><span>UPTIME</span><strong>{formatDuration(runtime.data.uptime_seconds)}</strong></div></div>
        <dl className="detail-list">
          <div><dt>构建版本</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>源码提交</dt><dd className="mono">{runtime.data.build_commit}</dd></div>
          <div><dt>启动时间</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>管理权限</dt><dd>read-only</dd></div>
        </dl>
      </Panel>
      <Panel title="控制面状态" subtitle="不是业务数据面吞吐">
        <div className="system-metrics"><div><span>待处理信令</span><strong>{overview.data.pending_signals}</strong></div><div><span>活动隧道</span><strong>{overview.data.active_tunnels}</strong></div><div><span>在线设备</span><strong>{overview.data.online_devices}</strong></div><div><span>账号</span><strong>{overview.data.users}</strong></div></div>
        <div className="truth-notice system-notice"><CircleAlert size={15} /><span>Control healthy、设备 online、Relay RTT 都不能单独证明真实 TUN 或应用流量已经端到端可达。</span></div>
      </Panel>
    </section>
  </div>
}

function AuthenticatedApp({ onLogout }: { onLogout: () => void }) {
  return <BrowserRouter basename="/admin"><Routes>
    <Route element={<Shell onLogout={onLogout} />}>
      <Route index element={<Dashboard />} />
      <Route path="accounts" element={<AccountsPage />} />
      <Route path="accounts/:id" element={<AccountDetailPage />} />
      <Route path="topology" element={<TopologyPage />} />
      <Route path="devices" element={<DevicesPage />} />
      <Route path="networks" element={<NetworksPage />} />
      <Route path="system" element={<SystemPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes></BrowserRouter>
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(Boolean(getAdminToken()))
  const queryClient = useQueryClient()
  useEffect(() => {
    const unauthorized = () => {
      // A rejected token must not leave the previous session's pages in the
      // cache, or the next login would briefly render the old session's data.
      queryClient.clear()
      setAuthenticated(false)
    }
    window.addEventListener('p2wlan:unauthorized', unauthorized)
    return () => window.removeEventListener('p2wlan:unauthorized', unauthorized)
  }, [queryClient])
  return authenticated ? <AuthenticatedApp onLogout={() => setAuthenticated(false)} /> : <Login onSuccess={() => setAuthenticated(true)} />
}
