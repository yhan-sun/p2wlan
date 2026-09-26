import { tr } from './i18n'
import { getLocale, setLocale, useLocale } from './i18n'
import {
  type FormEvent,
  type CSSProperties,
  type ReactNode,
  lazy,
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
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock3,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Moon,
  MonitorSmartphone,
  Network,
  RadioTower,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Sun,
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
import { AsyncView } from './AsyncView'
import { AccountScopePicker } from './AccountScopePicker'
import { mergeTopologyPages } from './topologyPaging'
import { summarizeNetworks, topologyForNetwork, type NetworkSummary } from './relationships'
import { usePageState, useCursorPage, connectionLink, relationshipLink } from './pageState'
import { QueryStatus, RefreshToggle, useAutoRefresh } from './refresh'
import { setTheme, useTheme } from './theme'
import type {
  AdminAccount,
  AdminDevice,
  AdminNetwork,
  AdminRoom,
  AdminTopology,
} from './types'

const PAGE_SIZE = 25
const ConnectionsPage = lazy(() => import('./ConnectionsPage').then((module) => ({ default: module.ConnectionsPage })))
const ConnectionHealthPage = lazy(() => import('./ConnectionHealthPage').then((module) => ({ default: module.ConnectionHealthPage })))
const TopologyCanvas = lazy(() => import('./TopologyCanvas').then((module) => ({ default: module.TopologyCanvas })))

function formatAgo(unix?: number): string {
  if (!unix) return tr('从未')
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unix)
  const locale = getLocale()
  if (seconds < 45) return tr('刚刚')
  if (seconds < 3600) {
    const count = Math.max(1, Math.floor(seconds / 60))
    return locale === 'zh-CN' ? `${count} 分钟前` : `${count} min ago`
  }
  if (seconds < 86400) {
    const count = Math.floor(seconds / 3600)
    return locale === 'zh-CN' ? `${count} 小时前` : `${count} hr ago`
  }
  if (seconds < 86400 * 30) {
    const count = Math.floor(seconds / 86400)
    return locale === 'zh-CN' ? `${count} 天前` : `${count} days ago`
  }
  return new Intl.DateTimeFormat(locale, { month: '2-digit', day: '2-digit', year: 'numeric' }).format(new Date(unix * 1000))
}

function formatDate(unix?: number): string {
  if (!unix) return '—'
  return new Intl.DateTimeFormat(getLocale(), {
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
  if (getLocale() === 'en-US') {
    if (days) return `${days}d ${hours}h`
    if (hours) return `${hours}h ${minutes}m`
    return `${minutes}m`
  }
  if (days) return `${days} 天 ${hours} 小时`
  if (hours) return `${hours} 小时 ${minutes} 分钟`
  return `${minutes} 分钟`
}

function natLabel(value: string): string {
  if (!value || value.toLowerCase() === 'unknown') return tr('Unknown')
  const match = value.match(/(?:^|;)m=([^;]+)/i)
  const normalized = (match?.[1] ?? value).replaceAll('_', ' ')
  return tr(getLocale() === 'zh-CN' ? normalized.toLowerCase() : normalized)
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
  return <span className={`account-mark ${size}`} style={{
    '--account-mark-color': color,
    color,
    background: colorWithAlpha(color, 0.12),
    borderColor: colorWithAlpha(color, 0.22),
  } as CSSProperties}>{initials}</span>
}

function Status({ online }: { online: boolean }) {
  return <span className={`status-label ${online ? 'online' : ''}`}><span />{tr(online ? '在线' : '离线')}</span>
}

function LoadingBlock({ label = '加载中…' }: { label?: string }) {
  return <div className="loading-block"><div className="spinner" />{tr(label)}</div>
}

function ErrorBlock({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : '加载失败'
  return <div className="error-block"><CircleAlert size={18} /><div><strong>{tr("无法加载数据")}</strong><span>{tr(message)}</span></div></div>
}

// A paused query (the browser is offline) is neither loading nor failed:
// react-query keeps isPending true while isFetching is false, so gating a page
// on isLoading would render nothing at all, with no message and no retry hint.
function PendingBlock({ queries, label = '加载中…' }: { queries: { fetchStatus: string }[]; label?: string }) {
  if (queries.some((query) => query.fetchStatus === 'paused')) {
    return <ErrorBlock error={new Error('浏览器当前离线，无法访问控制面。网络恢复后会自动重新请求。')} />
  }
  return <LoadingBlock label={label} />
}

// Control owns whether a live Direct/Relay path is observable at all. Render the
// control plane's own statement, and only fall back to the localized
// explanation while the control plane confirms the path is not observable —
// otherwise the console would keep asserting something it no longer knows.
function PathNotice({ data, fallback }: { data?: AdminTopology; fallback: string }) {
  const note = data?.path_observation_available ? data.path_observation_note : ''
  return <div className="truth-notice"><CircleAlert size={15} /><span>{tr(note || fallback)}</span></div>
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
  const rows = table.getRowModel().rows
  return <div className="data-table-container">
    <div className="data-table-wrap"><table className="data-table">
      <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => {
        const heading = header.column.columnDef.header
        return <th key={header.id}>{header.isPlaceholder ? null : typeof heading === 'string' ? tr(heading) : flexRender(heading, header.getContext())}</th>
      })}</tr>)}</thead>
      <tbody>
        {rows.map((row) => <tr key={row.id} className={onRowClick ? 'clickable' : ''} tabIndex={onRowClick ? 0 : undefined} onClick={() => onRowClick?.(row.original)} onKeyDown={(event) => {
          if (onRowClick && (event.key === 'Enter' || event.key === ' ')) {
            event.preventDefault()
            onRowClick(row.original)
          }
        }}>{row.getVisibleCells().map((cell) => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}
        {data.length === 0 && <tr><td className="table-empty" colSpan={columns.length}>{tr(empty)}</td></tr>}
      </tbody>
    </table></div>
    <div className="data-mobile-list">
      {rows.map((row) => {
        const cells = row.getVisibleCells().filter((cell) => {
          const heading = table.getColumn(cell.column.id)?.columnDef.header
          return typeof heading === 'string' && heading.trim().length > 0
        })
        const [primary, ...details] = cells
        const content = <>
          {primary && <div className="data-mobile-card-primary">{flexRender(primary.column.columnDef.cell, primary.getContext())}</div>}
          <div className="data-mobile-facts">
            {details.map((cell) => <div className="data-mobile-fact" key={cell.id}>
              <span>{tr(table.getColumn(cell.column.id)?.columnDef.header as string)}</span>
              <div>{flexRender(cell.column.columnDef.cell, cell.getContext())}</div>
            </div>)}
          </div>
        </>
        return onRowClick
          ? <button type="button" className="data-mobile-card clickable" key={row.id} onClick={() => onRowClick(row.original)}>{content}</button>
          : <article className="data-mobile-card" key={row.id}>{content}</article>
      })}
      {rows.length === 0 && <div className="data-mobile-empty">{tr(empty)}</div>}
    </div>
  </div>
}

function Pagination({ total, offset, limit, onChange }: { total: number; offset: number; limit: number; onChange: (offset: number) => void }) {
  const start = total === 0 || offset >= total ? 0 : offset + 1
  const end = start === 0 ? 0 : Math.min(total, offset + limit)
  return <div className="pagination-v2"><span>{start}{tr("–")}{end} {tr("/ ")}{total}</span><div>
    <button className="button secondary compact" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}><ChevronLeft size={15} />{tr("上一页")}</button>
    <button className="button secondary compact" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>{tr("下一页")}<ChevronRight size={15} /></button>
  </div></div>
}

function CursorPagination({ total, pageIndex, itemCount, canNext, canPrev = pageIndex > 0, previousIsFirst = false, onPrev, onNext }: {
  total: number
  pageIndex: number
  itemCount: number
  limit: number
  canNext: boolean
  canPrev?: boolean
  previousIsFirst?: boolean
  onPrev: () => void
  onNext: () => void
}) {
  return <div className="pagination-v2"><span>{tr('本页 ')}{itemCount}{tr(' 条 · 共 ')}{total}{tr(' 条')}</span><div>
    <button className="button secondary compact" disabled={!canPrev} onClick={onPrev}><ChevronLeft size={15} />{tr(previousIsFirst ? "返回首页" : "上一页")}</button>
    <button className="button secondary compact" disabled={!canNext} onClick={onNext}>{tr("下一页")}<ChevronRight size={15} /></button>
  </div></div>
}

function LanguageSwitch({ className = '' }: { className?: string }) {
  const locale = useLocale()
  return <div className={`locale-switch ${className}`} role="group" aria-label={tr('界面语言')}>
    <button type="button" className={locale === 'zh-CN' ? 'active' : ''} aria-pressed={locale === 'zh-CN'} title={tr('简体中文')} onClick={() => setLocale('zh-CN')}>中</button>
    <button type="button" className={locale === 'en-US' ? 'active' : ''} aria-pressed={locale === 'en-US'} title="English" onClick={() => setLocale('en-US')}>EN</button>
  </div>
}

function ThemeSwitch() {
  const theme = useTheme()
  const nextTheme = theme === 'dark' ? 'light' : 'dark'
  const label = tr(theme === 'dark' ? '切换到浅色主题' : '切换到深色主题')
  return <button type="button" className="theme-switch" onClick={() => setTheme(nextTheme)} title={label} aria-label={label}>
    {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
  </button>
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
      else setError(reason instanceof Error ? reason.message : '无法连接到控制面。')
    } finally {
      setSubmitting(false)
    }
  }

  return <main className="login-page-v2">
    <section className="login-brand-side">
      <div className="brand-lockup large"><div className="brand-symbol"><Waypoints size={22} /></div><div><strong>{tr("P2WLAN")}</strong><span>{tr("Control")}</span></div></div>
      <div className="login-brand-copy"><span className="eyebrow-v2">{tr("SELF-HOSTED CONTROL PLANE")}</span><h1>{tr("资源关系和真实路径，")}<br />{tr("各自说清楚。")}</h1><p>{tr("控制面资源关系与守护进程权威连接观测分开呈现，保持只读运维边界。")}</p></div>
      <div className="login-security"><ShieldCheck size={17} /><span>{tr("管理权限与用户 JWT / 设备凭据完全隔离")}</span></div>
    </section>
    <section className="login-form-side">
      <form className="login-card-v2" onSubmit={submit}>
        <div className="login-language-row"><span>{tr('界面语言')}</span><div className="login-appearance-controls"><ThemeSwitch /><LanguageSwitch /></div></div>
        <div className="mobile-brand"><div className="brand-symbol"><Waypoints size={20} /></div><strong>{tr("P2WLAN Control")}</strong></div>
        <span className="eyebrow-v2">{tr("ADMIN CONSOLE")}</span>
        <h2>{tr("登录控制台")}</h2>
        <p>{tr("输入部署时配置的 ")}<code>{tr("CONTROL_ADMIN_TOKEN")}</code>{tr("。")}</p>
        <label htmlFor="admin-token">{tr("管理员令牌")}</label>
        <div className="input-with-icon"><KeyRound size={16} /><input id="admin-token" type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder={tr("至少 32 个字符")} autoComplete="current-password" autoFocus /></div>
        <div className={`login-error ${error ? 'visible' : ''}`}>{tr(error) || ' '}</div>
        <button className="button primary login-button" type="submit" disabled={submitting}>{submitting ? <><div className="spinner light" />{tr("验证中…")}</> : <>{tr("进入控制台")}<ArrowRight size={16} /></>}</button>
        <div className="session-note"><CircleCheck size={14} />{tr("令牌仅保存在当前标签页会话中")}</div>
      </form>
    </section>
  </main>
}

const navGroups = [
  { label: '工作台', items: [
    { to: '/', end: true, icon: <LayoutDashboard size={17} />, label: '概览' },
    { to: '/accounts', icon: <Users size={17} />, label: '账号' },
  ] },
  { label: '资源管理', items: [
    { to: '/devices', icon: <MonitorSmartphone size={17} />, label: '设备' },
    { to: '/networks', icon: <Network size={17} />, label: '网络与房间' },
    { to: '/connections', icon: <RadioTower size={17} />, label: '连接观测' },
    { to: '/relationships', icon: <Waypoints size={17} />, label: '资源关系' },
  ] },
  { label: '运维', items: [
    { to: '/health', icon: <Gauge size={17} />, label: '连接健康' },
    { to: '/system', icon: <Activity size={17} />, label: '运行健康' },
  ] },
]

function pageMeta(pathname: string): { title: string; eyebrow: string } {
  if (pathname.startsWith('/accounts/')) return { title: '账号详情', eyebrow: 'ACCOUNTS' }
  if (pathname === '/accounts') return { title: '账号', eyebrow: 'ACCOUNTS' }
  if (pathname === '/relationships') return { title: '资源关系', eyebrow: 'RELATIONSHIPS' }
  if (pathname === '/connections') return { title: '连接观测', eyebrow: 'NETWORK' }
  if (pathname === '/devices') return { title: '设备', eyebrow: 'DEVICES' }
  if (pathname === '/networks') return { title: '网络与房间', eyebrow: 'NETWORK' }
  if (pathname === '/health') return { title: '连接健康', eyebrow: 'OPERATIONS' }
  if (pathname === '/system') return { title: '运行健康', eyebrow: 'OPERATIONS' }
  return { title: '概览', eyebrow: 'OVERVIEW' }
}

function Shell({ onLogout }: { onLogout: () => void }) {
  const refreshInterval = useAutoRefresh()
  const location = useLocation()
  const meta = pageMeta(location.pathname)
  const queryClient = useQueryClient()
  const runtime = useQuery({ queryKey: ['runtime-shell'], queryFn: ({ signal }) => adminApi.runtime(signal), refetchInterval: refreshInterval })
  const [refreshing, setRefreshing] = useState(false)

  useEffect(() => {
    window.scrollTo(0, 0)
  }, [location.pathname])

  const refresh = async () => {
    setRefreshing(true)
    try { await queryClient.invalidateQueries() } finally { window.setTimeout(() => setRefreshing(false), 250) }
  }

  return <div className="app-layout">
    <aside className="sidebar-v2">
      <Link to="/" className="brand-lockup"><div className="brand-symbol"><Waypoints size={20} /></div><div><strong>{tr("P2WLAN")}</strong><span>{tr("Control")}</span></div></Link>
      <nav className="sidebar-nav">{navGroups.map((group) => <div className="nav-group" key={group.label}><span className="nav-group-label">{tr(group.label)}</span>{group.items.map((item) => <NavLink key={item.to} to={item.to} end={item.end} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>{item.icon}<span>{tr(item.label)}</span></NavLink>)}</div>)}</nav>
      <div className="sidebar-runtime">
        <div className="runtime-line"><span className={`health-dot${runtime.isError ? ' down' : runtime.isPending || runtime.fetchStatus === 'paused' ? ' unknown' : ''}`} /><strong>{tr(runtime.fetchStatus === 'paused' ? '控制面状态待更新' : runtime.isError ? '控制面不可达' : runtime.isPending ? '正在检查控制面' : 'Control healthy')}</strong></div>
        <span>{runtime.data?.build_version ?? (runtime.isError ? '—' : tr('loading…'))}</span>
        <small>{tr("只读管理模式")}</small>
      </div>
    </aside>
    <div className="app-main">
      <header className="topbar-v2">
        <div><span className="topbar-eyebrow">{tr(meta.eyebrow)}</span><h1>{tr(meta.title)}</h1></div>
        <div className="topbar-actions-v2">
          <button className="icon-button-v2" onClick={refresh} title={tr("刷新数据")} aria-label={tr("刷新数据")}><RefreshCw size={17} className={refreshing ? 'spin' : ''} /></button>
          <RefreshToggle />
          <ThemeSwitch />
          <LanguageSwitch />
          <div className="topbar-divider" />
          <div className="user-identity"><span className="user-avatar" aria-hidden>AD</span><span className="user-menu-copy"><strong>{tr("admin")}</strong><small>{tr("read-only")}</small></span></div>
          <button className="icon-button-v2" title={tr('退出登录')} aria-label={tr('退出登录')} onClick={() => { clearAdminToken(); queryClient.clear(); onLogout() }}><LogOut size={17} /></button>
        </div>
      </header>
      <main className="page-content"><AsyncView key={location.pathname}><Outlet /></AsyncView></main>
    </div>
  </div>
}

function Dashboard() {
  const refreshInterval = useAutoRefresh()
  const overview = useQuery({ queryKey: ['overview'], queryFn: ({ signal }) => adminApi.overview(signal), refetchInterval: refreshInterval })
  const accounts = useQuery({ queryKey: ['accounts', 'recent'], queryFn: () => adminApi.accounts('', 6, 0), refetchInterval: refreshInterval })
  const runtime = useQuery({ queryKey: ['runtime'], queryFn: ({ signal }) => adminApi.runtime(signal), refetchInterval: refreshInterval })
  const connectionHealth = useQuery({
    queryKey: ['connection-health', 'dashboard', 3600],
    queryFn: () => adminApi.connectionHealth({ windowSeconds: 3600 }, 5),
    refetchInterval: refreshInterval,
  })
  if (overview.isPending || runtime.isPending) return <PendingBlock queries={[overview, runtime]} label={tr("正在读取控制面状态…")} />
  const error = overview.error || accounts.error || runtime.error
  if (error && (!overview.data || !runtime.data)) return <ErrorBlock error={error} />
  if (!overview.data || !runtime.data) return <ErrorBlock error={new Error('控制面未返回完整快照，请刷新重试。')} />

  const offlineDevices = Math.max(0, overview.data.devices - overview.data.online_devices)

  return <div className="page-stack">
    <QueryStatus queries={[overview, runtime, accounts, connectionHealth]} />
    <section className="metrics-grid-v2">
      <MetricCard icon={<Users size={18} />} label={tr("账号")} value={overview.data.users} meta={tr("控制面中的非系统账号")} />
          <MetricCard icon={<MonitorSmartphone size={18} />} label={tr("设备在线")} value={<>{overview.data.online_devices}{tr("/")}{overview.data.devices}</>} meta={offlineDevices
            ? getLocale() === 'zh-CN' ? <>{offlineDevices} 台离线</> : <>{offlineDevices} offline devices</>
            : tr('全部设备在线')} />
      <MetricCard icon={<Network size={18} />} label={tr("网络")} value={overview.data.networks} meta={<>{overview.data.rooms} {tr("个房间网络")}</>} />
      <MetricCard icon={<Activity size={18} />} label={tr("待处理信令")} value={overview.data.pending_signals} meta={<>{overview.data.active_tunnels} {tr("个控制面活动隧道")}</>} />
    </section>

    {connectionHealth.isPending
      ? <section className="dashboard-health-strip"><div className="dashboard-health-title"><span><Gauge size={16} /></span><div><strong>{tr("Connection Health")}</strong><small>{tr(connectionHealth.fetchStatus === 'paused' ? '当前离线，更新已暂停。' : '正在聚合最近 1 小时的路径信号…')}</small></div></div></section>
      : connectionHealth.error && !connectionHealth.data
        ? <section className="dashboard-health-strip"><div className="dashboard-health-title"><span><CircleAlert size={16} /></span><div><strong>{tr("连接健康暂不可用")}</strong><small>{tr(connectionHealth.error instanceof Error ? connectionHealth.error.message : '读取失败')}</small></div></div><Link to="/health">{tr("打开工作区")}<ArrowRight size={14} /></Link></section>
        : connectionHealth.data && <section className="dashboard-health-strip">
          <div className="dashboard-health-title"><span><Gauge size={16} /></span><div><strong>{tr("Connection Health · 1h")}</strong><small>{tr("派生信号，不是综合健康分")}</small></div></div>
          <div className="dashboard-health-fact"><strong>{connectionHealth.data.alerts_total}</strong><span>{tr("Needs attention")}</span></div>
          <div className="dashboard-health-fact"><strong>{connectionHealth.data.summary.fresh_direct}</strong><span>{tr("Fresh Direct")}</span></div>
          <div className="dashboard-health-fact"><strong>{connectionHealth.data.summary.fresh_relay}</strong><span>{tr("Fresh Relay")}</span></div>
          <div className="dashboard-health-fact"><strong>{connectionHealth.data.summary.recent_path_switches}</strong><span>{tr("Path switches")}</span></div>
          <Link to="/health">{tr("查看连接健康")}<ArrowRight size={14} /></Link>
        </section>}

    <section className="dashboard-grid operations-grid">
      <Panel className="health-card" title={tr("控制面运行健康")} subtitle={tr("这里只展示控制面能直接确认的事实")} action={<span className={`badge ${runtime.fetchStatus === 'paused' || runtime.error ? 'warning' : 'success'}`}><span />{tr(runtime.fetchStatus === 'paused' || runtime.error ? '缓存快照' : '可响应')}</span>}>
        <div className="health-runtime-big"><div className="health-runtime-icon"><Server size={22} /></div><div><span>{tr("运行时间")}</span><strong>{formatDuration(runtime.data.uptime_seconds)}</strong></div></div>
        <dl className="detail-list compact">
          <div><dt>{tr("版本")}</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>{tr("提交")}</dt><dd className="mono">{runtime.data.build_commit.slice(0, 10)}</dd></div>
          <div><dt>{tr("启动时间")}</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>{tr("管理权限")}</dt><dd>{tr("只读")}</dd></div>
        </dl>
        <Link className="text-link panel-footer-link" to="/system">{tr("查看运行健康")}<ArrowRight size={14} /></Link>
      </Panel>

      <Panel title={tr("需要关注")} subtitle={tr("按当前控制面快照生成，不推断真实数据面故障")}>
        <div className="attention-list">
          {offlineDevices > 0
            ? <div className="attention-item warning"><CircleAlert size={17} /><div><strong>{offlineDevices} {tr("台设备当前离线")}</strong><span>{tr("可到设备页按在线状态筛选，结合最后活动时间排查。")}</span></div><Link to="/devices?status=offline">{tr("查看")}</Link></div>
            : <div className="attention-item success"><CircleCheck size={17} /><div><strong>{tr("设备在线状态正常")}</strong><span>{tr("当前快照中没有离线设备。")}</span></div></div>}
          {overview.data.pending_signals > 0
            ? <div className="attention-item warning"><RadioTower size={17} /><div><strong>{overview.data.pending_signals} {tr("条待处理信令")}</strong><span>{tr("这是控制面协调状态，不代表 Relay 或 Direct 数据路径。")}</span></div><Link to="/relationships">{tr("查看关系")}</Link></div>
            : <div className="attention-item success"><CircleCheck size={17} /><div><strong>{tr("没有待处理信令")}</strong><span>{tr("控制面当前未记录积压的协调消息。")}</span></div></div>}
          <div className="attention-item neutral"><Waypoints size={17} /><div><strong>{tr("权威路径与资源关系已分离")}</strong><span>{tr("连接观测只读取守护进程已提交的权威数据；资源关系仍只表达成员关系与设备挂载。")}</span></div><Link to="/connections">{tr("查看连接")}</Link></div>
        </div>
      </Panel>
    </section>

    <section className="dashboard-lower-grid">
      <Panel title={tr("最近账号")} subtitle={tr("按设备最后活动时间排序")} action={<Link className="text-link" to="/accounts">{tr("全部账号")}<ArrowRight size={14} /></Link>}>
        <div className="recent-account-list">{accounts.isPending && <PendingBlock queries={[accounts]} />}{accounts.error && !accounts.data && <ErrorBlock error={accounts.error} />}{accounts.data?.items.map((account) => <Link className="recent-account-row" to={'/accounts/' + encodeURIComponent(account.id)} key={account.id}>
          <AccountMark account={account} />
          <div className="recent-account-main"><strong>{account.username}</strong><span>{account.email}</span></div>
          <div className="recent-account-stat"><strong>{account.online_devices}{tr("/")}{account.device_count}</strong><span>{tr("在线设备")}</span></div>
          <div className="recent-account-stat"><strong>{account.network_count}</strong><span>{tr("网络")}</span></div>
          <div className="recent-account-time">{formatAgo(account.last_seen)}</div>
          <ChevronRight size={15} />
        </Link>)}</div>
      </Panel>
      <Panel title={tr("控制面摘要")} subtitle={tr("计数不等于端到端业务可达")}>
        <div className="control-summary-grid">
          <div><span className="summary-icon"><Activity size={17} /></span><strong>{overview.data.pending_signals}</strong><small>{tr("待处理信令")}</small></div>
          <div><span className="summary-icon"><Waypoints size={17} /></span><strong>{overview.data.active_tunnels}</strong><small>{tr("活动隧道")}</small></div>
          <div><span className="summary-icon"><RadioTower size={17} /></span><strong>{overview.data.rooms}</strong><small>{tr("房间")}</small></div>
          <div><span className="summary-icon"><Clock3 size={17} /></span><strong>{formatAgo(overview.data.generated_at)}</strong><small>{tr("快照时间")}</small></div>
        </div>
      </Panel>
    </section>
  </div>
}
function AccountsPage() {
  const refreshInterval = useAutoRefresh()
  const navigate = useNavigate()
  const { params, update } = usePageState()
  const paging = useCursorPage()
  const query = params.get('q') || ''
  const debounced = useDebouncedValue(query)
  const result = useQuery({
    queryKey: ['accounts', 'cursor', debounced, paging.cursor],
    queryFn: ({ signal }) => adminApi.accountsCursor(debounced, paging.cursor, PAGE_SIZE, signal),
    refetchInterval: refreshInterval,
    enabled: debounced === query,
  })

  const columns = useMemo<ColumnDef<AdminAccount, unknown>[]>(() => [
    { id: 'account', header: '账号', cell: ({ row }) => <div className="identity-cell"><AccountMark account={row.original} /><div><strong>{row.original.username}</strong><span>{row.original.email}</span></div></div> },
    { id: 'devices', header: '设备', cell: ({ row }) => <div className="ratio-cell"><strong>{row.original.online_devices}{tr("/")}{row.original.device_count}</strong><span>{row.original.device_count ? Math.round(row.original.online_devices / row.original.device_count * 100) : 0}{tr("% 在线")}</span></div> },
    { accessorKey: 'network_count', header: '网络' },
    { accessorKey: 'room_count', header: '房间' },
    { id: 'last_seen', header: '最近活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
    { id: 'created_at', header: '注册时间', cell: ({ row }) => formatDate(row.original.created_at) },
    { id: 'action', header: '', cell: () => <ChevronRight className="row-chevron" size={16} /> },
  ], [])

  return <div className="page-stack">
    <div className="page-intro"><div><h2>{tr("所有账号")}</h2><p>{tr('查看账号的设备、网络和最近活动。')}</p></div><div className="search-field"><Search size={16} /><input value={query} onChange={(event) => update({ q: event.target.value, cursor: '', page: '' }, true)} placeholder={tr("搜索用户名或邮箱")} aria-label={tr("搜索用户名或邮箱")} /></div></div>
    <QueryStatus queries={[result]} />
    <Panel>
      {result.isPending || debounced !== query ? <PendingBlock queries={[result]} /> : result.error && !result.data ? <ErrorBlock error={result.error} /> : result.data ? <>
        <DataTable<AdminAccount> columns={columns} data={result.data.items} onRowClick={(account) => navigate(`/accounts/${encodeURIComponent(account.id)}`)} empty={tr("没有符合条件的账号")} />
        <CursorPagination
          total={result.data.total}
          pageIndex={paging.pageIndex}
          canPrev={paging.canPrev}
          previousIsFirst={paging.previousIsFirst}
          itemCount={result.data.items.length}
          limit={PAGE_SIZE}
          canNext={Boolean(result.data.next_cursor)}
          onPrev={paging.prev}
          onNext={() => paging.next(result.data?.next_cursor || '')}
        />
      </> : <ErrorBlock error={new Error('控制面未返回账号列表。')} />}
    </Panel>
  </div>
}

function DeviceTable({ devices }: { devices: AdminDevice[] }) {
  const columns = useMemo<ColumnDef<AdminDevice, unknown>[]>(() => [
    { id: 'device', header: '设备', cell: ({ row }) => <div className="primary-secondary"><Link to={connectionLink({ deviceId: row.original.id })}>{row.original.device_name}</Link><span>{row.original.platform} {tr("· ")}{row.original.app_version || tr('未知版本')}</span></div> },
    { id: 'network_name', header: '网络', cell: ({ row }) => <Link to={relationshipLink(row.original.network_id, row.original.owner_id)}>{row.original.network_name}</Link> },
    { id: 'ip', header: 'Virtual IP', cell: ({ row }) => <span className="mono">{row.original.virtual_ip}</span> },
    { id: 'nat', header: 'NAT', cell: ({ row }) => natLabel(row.original.nat_type) },
    { id: 'rtt', header: 'Relay RTT', cell: ({ row }) => row.original.relay_rtt_ms === undefined ? '—' : `${row.original.relay_rtt_ms} ms` },
    { id: 'status', header: '状态', cell: ({ row }) => <Status online={row.original.online} /> },
    { id: 'last', header: '最后活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
  ], [])
  return <DataTable<AdminDevice> columns={columns} data={devices} empty={tr("该账号还没有设备")} />
}

function NetworkTable({ networks }: { networks: AdminNetwork[] }) {
  const columns = useMemo<ColumnDef<AdminNetwork, unknown>[]>(() => [
    { id: 'name', header: '网络', cell: ({ row }) => <div className="primary-secondary"><Link to={relationshipLink(row.original.id, row.original.owner_id)}>{row.original.name}</Link><span className="mono">{row.original.id}</span></div> },
    { id: 'cidr', header: 'CIDR', cell: ({ row }) => <span className="mono">{row.original.cidr}</span> },
    { id: 'owner', header: '所有者', cell: ({ row }) => row.original.owner_id ? <Link to={`/accounts/${encodeURIComponent(row.original.owner_id)}`}>{row.original.owner_username}</Link> : row.original.owner_username },
    { accessorKey: 'member_count', header: 'Members' },
    { id: 'devices', header: '设备', cell: ({ row }) => `${row.original.online_devices}/${row.original.device_count} ${tr('在线')}` },
    { id: 'type', header: '类型', cell: ({ row }) => <span className={`badge ${row.original.is_room ? 'purple' : ''}`}>{tr(row.original.is_room ? '房间网络' : '普通网络')}</span> },
    { id: 'connections', header: '连接', cell: ({ row }) => <Link className="text-link" to={connectionLink({ networkId: row.original.id })}>{tr('查看连接')}</Link> },
  ], [])
  return <DataTable<AdminNetwork> columns={columns} data={networks} empty={tr("暂无网络")} />
}

function RoomTable({ rooms }: { rooms: AdminRoom[] }) {
  const columns = useMemo<ColumnDef<AdminRoom, unknown>[]>(() => [
    { id: 'name', header: '房间', cell: ({ row }) => <div className="primary-secondary"><Link to={relationshipLink(row.original.id, row.original.owner_id)}>{row.original.name}</Link><span className="mono">{tr("#")}{row.original.code}</span></div> },
    { id: 'cidr', header: 'CIDR', cell: ({ row }) => <span className="mono">{row.original.cidr}</span> },
    { id: 'owner', header: '所有者', cell: ({ row }) => row.original.owner_id ? <Link to={`/accounts/${encodeURIComponent(row.original.owner_id)}`}>{row.original.owner_username}</Link> : row.original.owner_username },
    { accessorKey: 'member_count', header: 'Members' },
    { id: 'devices', header: '设备', cell: ({ row }) => `${row.original.online_devices}/${row.original.device_count} ${tr('在线')}` },
    { id: 'join', header: '加入', cell: ({ row }) => <span className={`badge ${row.original.join_locked ? 'warning' : 'success'}`}>{tr(row.original.join_locked ? '已锁定' : '可加入')}</span> },
    { id: 'connections', header: '连接', cell: ({ row }) => <Link className="text-link" to={connectionLink({ networkId: row.original.id })}>{tr('查看连接')}</Link> },
  ], [])
  return <DataTable<AdminRoom> columns={columns} data={rooms} empty={tr("暂无房间")} />
}

function NetworkOverview({ data, search, onSelect }: {
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
        <span className="network-overview-stats"><strong>{item.onlineCount}<i>{tr("/")}{item.deviceCount}</i></strong><span>{tr(item.deviceCount === 1 ? 'device online' : 'devices online')}</span></span>
        <span className="network-overview-footer"><span>{item.memberCount} {tr(getLocale() === 'en-US' ? item.memberCount === 1 ? 'member' : 'members' : '位成员')}{item.owner ? ` · ${tr('所有者')} ${item.owner}` : ''}</span><span className="network-open-label">{tr("查看关系 ")}<ArrowUpRight size={14} /></span></span>
      </button>)}
    </div> : <div className="network-overview-empty"><Search size={18} /><strong>{tr("没有匹配的资源分组")}</strong><span>{tr('试试网络、账号或设备名称。')}</span></div>}
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

function NetworkRelationship({ data, summary, onBack, search = '' }: {
  data: AdminTopology
  summary: NetworkSummary
  onBack: () => void
  search?: string
}) {
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
      <button className="button secondary compact" onClick={onBack}><ChevronLeft size={15} />{tr("所有资源")}</button>
      <div><strong>{summary.node.label}{summary.personal ? ` · ${tr('个人设备')}` : ''}</strong><span>{summary.memberCount} {tr("位成员 · ")}{summary.onlineCount}{tr("/")}{summary.deviceCount} {tr("台设备在线")}</span></div>
      <Link className="button secondary compact" to={connectionLink(summary.personal ? { accountId: summary.node.account_id || summary.node.id.replace(/^account:/, ''), networkId: 'default' } : { networkId: summary.id })}>{tr('查看连接')}</Link>
      <div className="network-view-tabs" role="group" aria-label={tr("网络关系视图")}>
        <button aria-pressed={view === 'overview'} className={view === 'overview' ? 'active' : ''} onClick={() => setView('overview')}>{tr("资源概览")}</button>
        <button aria-pressed={view === 'graph'} className={view === 'graph' ? 'active' : ''} onClick={() => setView('graph')}>{tr("关系图")}</button>
      </div>
    </div>
    {view === 'graph' ? <AsyncView><TopologyCanvas data={scopedData} search={search} /></AsyncView> : <div className="network-resource-grid">
      <section className="network-resource-panel">
        <header><div><h3>{tr("成员")}</h3><span>{tr("此网络中的账号成员")}</span></div><b>{members.length}</b></header>
        <div className="network-resource-list">
          {members.map((member) => <div className="network-resource-row" key={member.id}>
            <AccountMark account={{ id: member.account_id || member.id, username: member.username || member.label }} size="small" />
            <div className="network-resource-copy"><Link to={`/accounts/${encodeURIComponent(member.account_id || member.id.replace(/^account:/, ''))}`}>{member.label}</Link><span>{tr((summary.personal || membershipRoles.get(member.id) === 'owner') ? '网络所有者' : '账号成员')}</span></div>
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
            <div className="network-resource-copy"><Link to={connectionLink({ deviceId: device.id.replace(/^device:/, '') })}>{device.label}</Link><span>{[device.username, device.virtual_ip, device.platform].filter(Boolean).join(' · ') || tr('设备信息未上报')}</span></div>
            <Status online={Boolean(device.online)} />
          </div>)}
          {devices.length === 0 && <div className="network-resource-empty">{tr(normalizedSearch ? '没有匹配的设备' : '暂无设备数据')}</div>}
        </div>
      </section>
    </div>}
  </>
}

function AccountDetailPage() {
  const refreshInterval = useAutoRefresh()
  const { id = '' } = useParams()
  const { params, update } = usePageState()
  const tab = ['devices', 'networks', 'rooms'].includes(params.get('tab') || '') ? params.get('tab')! : 'topology'
  const selectedNetworkId = params.get('network_id') || ''
  const setSelectedNetworkId = (networkId: string) => update({ network_id: networkId })
  const setTab = (value: string) => update({ tab: value === 'topology' ? '' : value })
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [selectedNetworkId, tab])
  const detail = useQuery({ queryKey: ['account', id], queryFn: ({ signal }) => adminApi.account(id, signal), enabled: Boolean(id), refetchInterval: refreshInterval })
  const topology = useQuery({ queryKey: ['topology', 'account', id], queryFn: ({ signal }) => adminApi.topology(id, signal), enabled: Boolean(id), refetchInterval: refreshInterval })
  const accountNetworks = useMemo(() => summarizeNetworks(topology.data), [topology.data])
  if (detail.isPending) return <PendingBlock queries={[detail]} label={tr("正在加载账号…")} />
  if (detail.error && !detail.data) return <ErrorBlock error={detail.error} />
  if (!detail.data) return <ErrorBlock error={new Error('控制面未返回该账号详情，请返回账号列表重试。')} />
  const account = detail.data.account
  const color = accountColor(account.id)
  const selectedNetwork = accountNetworks.find((network) => network.id === selectedNetworkId)

  return <div className="page-stack">
    <QueryStatus queries={tab === 'topology' ? [detail, topology] : [detail]} />
    <div className="detail-navigation"><Link className="text-link" to="/accounts"><ChevronLeft size={15} />{tr('所有账号')}</Link><Link className="button secondary compact" to={connectionLink({ accountId: id })}>{tr('查看账号连接')}<ArrowRight size={15} /></Link></div>
    <section className="account-hero">
      <AccountMark account={account} size="large" />
      <div className="account-hero-copy"><span className="account-color-label" style={{ '--account-mark-color': color } as CSSProperties}>{tr("ACCOUNT")}</span><h2>{account.username}</h2><p>{account.email}</p></div>
      <div className="account-hero-stats"><div><strong>{account.device_count}</strong><span>{tr("设备")}</span></div><div><strong className="positive-text">{account.online_devices}</strong><span>{tr("在线")}</span></div><div><strong>{account.network_count}</strong><span>{tr("网络")}</span></div><div><strong>{account.room_count}</strong><span>{tr("房间")}</span></div></div>
    </section>

    <div className="tabs-v2">
      {([['topology', tr('关系')], ['devices', `${tr('设备')} ${account.device_count}`], ['networks', `${tr('网络')} ${account.network_count}`], ['rooms', `${tr('房间')} ${account.room_count}`]] as const).map(([value, label]) => <button key={value} className={tab === value ? 'active' : ''} onClick={() => setTab(value)}>{label}</button>)}
    </div>

    {tab === 'topology' && <Panel title={getLocale() === 'zh-CN' ? `${account.username} 的资源关系` : `Relationships for ${account.username}`} subtitle={tr("按网络查看成员、设备及控制面资源关系")}>
      <PathNotice data={topology.data} fallback={tr("这是控制面资源关系图：仅展示成员关系、设备挂载和可选的待处理信令。守护进程权威路径观测保存在独立的连接观测工作区，不会混入资源关系。")} />
      {selectedNetwork && topology.data
        ? <NetworkRelationship key={`${id}:${selectedNetwork.id}`} data={topology.data} summary={selectedNetwork} onBack={() => setSelectedNetworkId('')} />
        : topology.data && <NetworkOverview data={topology.data} search="" onSelect={setSelectedNetworkId} />}
      {topology.isPending && <LoadingBlock label={tr("正在构建网络关系…")} />}
      {topology.error && <ErrorBlock error={topology.error} />}
    </Panel>}
    {tab === 'devices' && <Panel><DeviceTable devices={detail.data.devices} /></Panel>}
    {tab === 'networks' && <Panel><NetworkTable networks={detail.data.networks} /></Panel>}
    {tab === 'rooms' && <Panel><RoomTable rooms={detail.data.rooms} /></Panel>}
  </div>
}

function RelationshipsPage() {
  const refreshInterval = useAutoRefresh()
  const { params, update } = usePageState()
  const accountId = params.get('account_id') || ''
  const selectedNetworkId = params.get('network_id') || ''
  const search = params.get('q') || ''
  const detailSearch = params.get('resource_q') || ''
  const setSelectedNetworkId = (networkId: string) => update({ network_id: networkId, resource_q: '' })
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [accountId, selectedNetworkId])
  const accountTopology = useQuery({
    queryKey: ['relationships', 'account', accountId],
    queryFn: ({ signal }) => adminApi.topology(accountId, signal),
    enabled: Boolean(accountId),
    refetchInterval: refreshInterval,
  })
  const globalTopology = useInfiniteQuery({
    queryKey: ['relationships', 'global-paged'],
    queryFn: ({ pageParam, signal }) => adminApi.topologyPage(pageParam, 12, 600, signal),
    refetchInterval: refreshInterval,
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
  const networkSummaries = useMemo(() => summarizeNetworks(relationshipData), [relationshipData])
  const selectedNetwork = networkSummaries.find((network) => network.id === selectedNetworkId)
  const account = accountId ? { id: accountId, username: accountTopology.data?.nodes.find((node) => node.id === `account:${accountId}`)?.label || params.get('account_name') || accountId } : null

  return <div className="page-stack topology-page-stack">
    <div className="page-intro topology-toolbar"><div><h2>{selectedNetwork?.node.label || tr(accountId ? '账号资源关系' : '资源关系')}</h2><p>{tr(selectedNetwork?.personal ? '此分组只展示所选账号的个人设备。' : selectedNetwork ? '当前视图展示此网络的成员和设备关系。' : '选择网络或个人设备分组，查看成员和设备关系。')}</p></div><div className="toolbar-controls topology-toolbar-controls">
      <div className="search-field"><Search size={16} /><input value={selectedNetworkId ? detailSearch : search} onChange={(event) => update({ [selectedNetworkId ? 'resource_q' : 'q']: event.target.value }, true)} placeholder={tr("搜索网络、成员、设备或 IP")} aria-label={tr("搜索网络、成员、设备或 IP")} /></div>
      <select className="select-field" aria-label={tr('选择资源分组')} value={selectedNetworkId} onChange={(event) => setSelectedNetworkId(event.target.value)} disabled={!networkSummaries.length}><option value="">{tr("选择资源分组")}</option>{networkSummaries.map((network) => <option value={network.id} key={network.id}>{network.personal ? `${network.node.label} · ${tr('个人设备')}` : network.node.label}</option>)}</select>
      <AccountScopePicker value={account} onChange={(next) => update({ account_id: next?.id || '', account_name: next?.username || '', network_id: '', resource_q: '' })} />
    </div></div>
    <QueryStatus queries={[accountId ? accountTopology : globalTopology]} />
    <Panel className="topology-main-panel">
      <div className="truth-notice topology-truth"><CircleAlert size={15} /><span>{tr("连线表示成员关系和设备挂载等控制面资源关系。Direct / Relay 的实时路径观测请到「连接观测」查看；两类数据不会互相推断。")}</span></div>
      {!accountId && globalData && <div className="topology-page-progress">
        <span>{tr("已加载 ")}{globalData.loaded_accounts} {tr("/ ")}{globalData.total_accounts} {tr("个账号")}</span>
        {globalData.partial
          ? <span className="topology-partial-warning">{tr('当前只显示部分资源，请选择具体账号查看详情。')}</span>
          : globalTopology.hasNextPage
            ? <button className="button secondary compact" onClick={() => globalTopology.fetchNextPage()} disabled={globalTopology.isFetchingNextPage}>{globalTopology.isFetchingNextPage ? tr('加载中…') : tr('加载更多账号')}</button>
            : <span className="badge success"><span />{tr("全局账号已加载完成")}</span>}
      </div>}
      {relationshipPending && <LoadingBlock label={tr("正在读取网络关系…")} />}
      {relationshipError && !relationshipData && <ErrorBlock error={relationshipError} />}
      {!relationshipPending && relationshipData && (selectedNetwork
        ? <NetworkRelationship key={`${accountId}:${selectedNetwork.id}`} data={relationshipData} summary={selectedNetwork} onBack={() => setSelectedNetworkId('')} search={detailSearch} />
        : <NetworkOverview data={relationshipData} search={search} onSelect={setSelectedNetworkId} />)}
      {selectedNetworkId && relationshipData && !selectedNetwork && <p className="query-status">{tr('当前范围未找到所选资源，请重新选择账号或网络。')}</p>}
    </Panel>
  </div>
}
function DevicesPage() {
  const refreshInterval = useAutoRefresh()
  const { params, update } = usePageState()
  const paging = useCursorPage()
  const query = params.get('q') || ''
  const status = ['online', 'offline'].includes(params.get('status') || '') ? params.get('status')! : 'all'
  const debounced = useDebouncedValue(query)
  const result = useQuery({
    queryKey: ['devices', 'cursor', debounced, status, paging.cursor],
    queryFn: ({ signal }) => adminApi.devicesCursor(debounced, status, paging.cursor, PAGE_SIZE, signal),
    refetchInterval: refreshInterval,
    enabled: debounced === query,
  })
  const columns = useMemo<ColumnDef<AdminDevice, unknown>[]>(() => [
    { id: 'device', header: '设备', cell: ({ row }) => <div className="primary-secondary"><Link to={connectionLink({ deviceId: row.original.id })}>{row.original.device_name}</Link><span>{row.original.platform} {tr("· ")}{row.original.app_version || tr('未知版本')}</span></div> },
    { id: 'username', header: '账号', cell: ({ row }) => row.original.owner_id ? <Link to={`/accounts/${encodeURIComponent(row.original.owner_id)}`}>{row.original.username}</Link> : row.original.username },
    { id: 'network_name', header: '网络', cell: ({ row }) => <Link to={relationshipLink(row.original.network_id, row.original.owner_id)}>{row.original.network_name}</Link> },
    { id: 'ip', header: 'Virtual IP', cell: ({ row }) => <span className="mono">{row.original.virtual_ip}</span> },
    { id: 'nat', header: 'NAT', cell: ({ row }) => natLabel(row.original.nat_type) },
    { id: 'rtt', header: 'Relay RTT', cell: ({ row }) => row.original.relay_rtt_ms === undefined ? '—' : `${row.original.relay_rtt_ms} ms` },
    { id: 'status', header: '状态', cell: ({ row }) => <Status online={row.original.online} /> },
    { id: 'last', header: '最后活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
  ], [])

  return <div className="page-stack">
    <div className="page-intro"><div><h2>{tr("设备")}</h2><p>{tr("全部账号下已注册的 P2WLAN 设备。")}</p></div><div className="toolbar-controls"><div className="search-field"><Search size={16} /><input value={query} onChange={(event) => update({ q: event.target.value, cursor: '', page: '' }, true)} placeholder={tr("搜索设备、账号、IP 或网络")} aria-label={tr("搜索设备、账号、IP 或网络")} /></div><select className="select-field" value={status} onChange={(event) => update({ status: event.target.value === 'all' ? '' : event.target.value, cursor: '', page: '' })} aria-label={tr("全部状态")}><option value="all">{tr("全部状态")}</option><option value="online">{tr("在线")}</option><option value="offline">{tr("离线")}</option></select></div></div>
    <QueryStatus queries={[result]} />
    <Panel>{result.isPending || debounced !== query ? <PendingBlock queries={[result]} /> : result.error && !result.data ? <ErrorBlock error={result.error} /> : result.data ? <><DataTable<AdminDevice> columns={columns} data={result.data.items} /><CursorPagination total={result.data.total} pageIndex={paging.pageIndex} itemCount={result.data.items.length} limit={PAGE_SIZE} canNext={Boolean(result.data.next_cursor)} canPrev={paging.canPrev} previousIsFirst={paging.previousIsFirst} onPrev={paging.prev} onNext={() => paging.next(result.data?.next_cursor || '')} /></> : <ErrorBlock error={new Error('控制面未返回设备列表。')} />}</Panel>
  </div>
}

function NetworksPage() {
  const refreshInterval = useAutoRefresh()
  const { params, update } = usePageState()
  const tab = params.get('tab') === 'rooms' ? 'rooms' : 'networks'
  const pageOffset = (key: string) => {
    const value = Number(params.get(key))
    return Number.isSafeInteger(value) && value > 0 && value <= 100_000 ? value * PAGE_SIZE : 0
  }
  const networkOffset = pageOffset('network_page')
  const roomOffset = pageOffset('room_page')
  const networks = useQuery({
    queryKey: ['networks', networkOffset],
    queryFn: ({ signal }) => adminApi.networks(PAGE_SIZE, networkOffset, signal),
    enabled: tab === 'networks', refetchInterval: refreshInterval,
  })
  const rooms = useQuery({
    queryKey: ['rooms', roomOffset],
    queryFn: ({ signal }) => adminApi.rooms(PAGE_SIZE, roomOffset, signal),
    enabled: tab === 'rooms', refetchInterval: refreshInterval,
  })
  const active = tab === 'networks' ? networks : rooms
  const offset = tab === 'networks' ? networkOffset : roomOffset
  const pageKey = tab === 'networks' ? 'network_page' : 'room_page'
  const total = active.data?.total
  useEffect(() => {
    if (total !== undefined && offset > 0 && offset >= total) {
      update({ [pageKey]: String(Math.max(0, Math.ceil(total / PAGE_SIZE) - 1)) }, true)
    }
  }, [total, offset, pageKey])

  return <div className="page-stack">
    <div className="page-intro"><div><h2>{tr('网络与房间')}</h2><p>{tr('查看网络、房间和成员，进入关系或连接详情继续排查。')}</p></div></div>
    <div className="tabs-v2">
      <button aria-pressed={tab === 'networks'} className={tab === 'networks' ? 'active' : ''} onClick={() => update({ tab: '' })}>{tr('网络')}{networks.data ? ` ${networks.data.total}` : ''}</button>
      <button aria-pressed={tab === 'rooms'} className={tab === 'rooms' ? 'active' : ''} onClick={() => update({ tab: 'rooms' })}>{tr('房间')}{rooms.data ? ` ${rooms.data.total}` : ''}</button>
    </div>
    <QueryStatus queries={[active]} />
    <Panel>{active.isPending ? <PendingBlock queries={[active]} /> : active.error && !active.data ? <ErrorBlock error={active.error} /> : <>
      {tab === 'networks' && networks.data && <NetworkTable networks={networks.data.items} />}
      {tab === 'rooms' && rooms.data && <RoomTable rooms={rooms.data.items} />}
      {active.data && <Pagination total={active.data.total} offset={offset} limit={PAGE_SIZE} onChange={(value) => update({ [pageKey]: value ? String(value / PAGE_SIZE) : '' })} />}
    </>}</Panel>
  </div>
}

function SystemPage() {
  const refreshInterval = useAutoRefresh()
  const runtime = useQuery({ queryKey: ['runtime-system'], queryFn: ({ signal }) => adminApi.runtime(signal), refetchInterval: refreshInterval })
  const overview = useQuery({ queryKey: ['overview-system'], queryFn: ({ signal }) => adminApi.overview(signal), refetchInterval: refreshInterval })
  if (runtime.isPending || overview.isPending) return <PendingBlock queries={[runtime, overview]} />
  const error = runtime.error || overview.error
  if (error && (!overview.data || !runtime.data)) return <ErrorBlock error={error} />
  if (!runtime.data || !overview.data) return <ErrorBlock error={new Error('控制面未返回完整的运行状态快照。')} />
  return <div className="page-stack">
    <QueryStatus queries={[runtime, overview]} />
    <div className="page-intro"><div><h2>{tr("控制面运行健康")}</h2><p>{tr("这里只展示控制面进程与数据库能直接确认的事实；Relay TLS、systemd、SQLite 完整性和备份请在部署主机运行 ")}<code>{tr("p2wlan-server doctor")}</code>{tr("。")}</p></div><span className={`badge ${runtime.fetchStatus === 'paused' || runtime.error ? 'warning' : 'success'} large`}><span />{tr(runtime.fetchStatus === 'paused' || runtime.error ? '缓存快照' : '运行中')}</span></div>
    <section className="system-grid">
      <Panel title={tr("进程")} subtitle={tr("构建与启动信息")}>
        <div className="system-hero"><div className="system-hero-icon"><Server size={26} /></div><div><span>{tr("UPTIME")}</span><strong>{formatDuration(runtime.data.uptime_seconds)}</strong></div></div>
        <dl className="detail-list">
          <div><dt>{tr("构建版本")}</dt><dd>{runtime.data.build_version}</dd></div>
          <div><dt>{tr("源码提交")}</dt><dd className="mono">{runtime.data.build_commit}</dd></div>
          <div><dt>{tr("启动时间")}</dt><dd>{formatDate(runtime.data.started_at)}</dd></div>
          <div><dt>{tr("管理权限")}</dt><dd>{tr("read-only")}</dd></div>
        </dl>
      </Panel>
      <Panel title={tr("控制面状态")} subtitle={tr("不是业务数据面吞吐")}>
        <div className="system-metrics"><div><span>{tr("待处理信令")}</span><strong>{overview.data.pending_signals}</strong></div><div><span>{tr("活动隧道")}</span><strong>{overview.data.active_tunnels}</strong></div><div><span>{tr("在线设备")}</span><strong>{overview.data.online_devices}</strong></div><div><span>{tr("账号")}</span><strong>{overview.data.users}</strong></div></div>
        <div className="truth-notice system-notice"><CircleAlert size={15} /><span>{tr("控制面正常、设备在线和 Relay RTT 都不能单独证明真实 TUN 或应用流量已端到端可达。主机级部署问题请使用 p2wlan-server doctor 分层检查。")}</span></div>
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
      <Route path="relationships" element={<RelationshipsPage />} />
      <Route path="topology" element={<Navigate to="/relationships" replace />} />
      <Route path="connections" element={<ConnectionsPage />} />
      <Route path="devices" element={<DevicesPage />} />
      <Route path="networks" element={<NetworksPage />} />
      <Route path="health" element={<ConnectionHealthPage />} />
      <Route path="system" element={<SystemPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes></BrowserRouter>
}

export default function App() {
  const locale = useLocale()
  const [authenticated, setAuthenticated] = useState(Boolean(getAdminToken()))
  const queryClient = useQueryClient()
  useEffect(() => {
    document.documentElement.lang = locale
  }, [locale])
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
