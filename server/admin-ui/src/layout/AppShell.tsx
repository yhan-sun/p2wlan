import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, ChevronRight, LayoutDashboard, Menu, MonitorSmartphone, Network, PanelLeftClose, PanelLeftOpen, RadioTower, RefreshCw, ShieldCheck, Users, Waypoints, X } from 'lucide-react'
import { type ReactNode, useEffect, useRef, useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { AsyncView } from '../AsyncView'
import { ConsolePreferences, ThemeSwitch } from '../ConsolePreferences'
import { adminApi, clearAdminToken } from '../api'
import { IconButton } from '../components/ui/console'
import { getLocale, tr } from '../i18n'
import { useAutoRefresh } from '../refresh'
import { useOverlay } from '../useOverlay'

const navGroups: { label: string; items: { to: string; end?: boolean; icon: ReactNode; label: string }[] }[] = [
  { label: '概览', items: [
    { to: '/', end: true, icon: <LayoutDashboard size={17} />, label: '概览' },
  ] },
  { label: '资源', items: [
    { to: '/accounts', icon: <Users size={17} />, label: '账号' },
    { to: '/devices', icon: <MonitorSmartphone size={17} />, label: '设备' },
    { to: '/networks', icon: <Network size={17} />, label: '网络与房间' },
    { to: '/relationships', icon: <Waypoints size={17} />, label: '资源关系' },
  ] },
  { label: '运维', items: [
    { to: '/connections', icon: <RadioTower size={17} />, label: '连接排障' },
    { to: '/system', icon: <Activity size={17} />, label: '运行状态' },
  ] },
]

function pageMeta(pathname: string): { title: string; eyebrow: string } {
  if (pathname.startsWith('/accounts/')) return { title: '账号详情', eyebrow: 'ACCOUNTS' }
  if (pathname === '/accounts') return { title: '账号', eyebrow: 'ACCOUNTS' }
  if (pathname === '/relationships') return { title: '资源关系', eyebrow: 'RELATIONSHIPS' }
  if (pathname === '/connections' || pathname === '/health') return { title: '连接排障', eyebrow: 'OPERATIONS' }
  if (pathname === '/devices') return { title: '设备', eyebrow: 'DEVICES' }
  if (pathname === '/networks') return { title: '网络与房间', eyebrow: 'NETWORK' }
  if (pathname === '/system') return { title: '运行状态', eyebrow: 'OPERATIONS' }
  return { title: '概览', eyebrow: 'OVERVIEW' }
}

export function Shell({ onLogout }: { onLogout: () => void }) {
  const location = useLocation()
  const meta = pageMeta(location.pathname)
  const queryClient = useQueryClient()
  const refreshInterval = useAutoRefresh()
  const runtime = useQuery({ queryKey: ['runtime'], queryFn: ({ signal }) => adminApi.runtime(signal), refetchInterval: refreshInterval })
  const [refreshing, setRefreshing] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [mobile, setMobile] = useState(() => window.matchMedia('(max-width: 900px)').matches)
  const navTrigger = useRef<HTMLButtonElement>(null)
  const navClose = useRef<HTMLButtonElement>(null)
  const sidebar = useRef<HTMLElement>(null)
  const main = useRef<HTMLElement>(null)
  const previousPath = useRef(location.pathname)
  const closeNavigation = () => {
    setMobileOpen(false)
    // Wait until the closed dialog releases inert from the page.
    window.requestAnimationFrame(() => navTrigger.current?.focus())
  }
  useOverlay(mobileOpen, closeNavigation)

  useEffect(() => {
    const media = window.matchMedia('(max-width: 900px)')
    const sync = () => { setMobile(media.matches); if (!media.matches) setMobileOpen(false) }
    media.addEventListener('change', sync)
    return () => media.removeEventListener('change', sync)
  }, [])
  useEffect(() => {
    if (mobileOpen) navClose.current?.focus()
  }, [mobileOpen])
  useEffect(() => {
    window.scrollTo(0, 0)
    setMobileOpen(false)
    if (previousPath.current !== location.pathname) main.current?.focus({ preventScroll: true })
    previousPath.current = location.pathname
  }, [location.pathname])

  const refresh = async () => {
    setRefreshing(true)
    try { await queryClient.invalidateQueries() } finally { setRefreshing(false) }
  }
  const runtimeSnapshot = !refreshInterval || runtime.fetchStatus === 'paused' || Boolean(runtime.error)
  const runtimeTime = runtime.dataUpdatedAt ? new Intl.DateTimeFormat(getLocale(), { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(runtime.dataUpdatedAt) : ''
  const runtimeLabel = tr(runtime.fetchStatus === 'paused' ? '控制面状态待更新' : runtime.isError ? '控制面检查失败' : runtime.isPending ? '正在检查控制面' : runtimeSnapshot ? '控制面快照' : '上次检查可达')

  return <div className={`app-layout ${sidebarCollapsed ? 'sidebar-collapsed' : ''} ${mobileOpen ? 'mobile-nav-open' : ''}`}>
    <a className="skip-link" href="#main-content" inert={mobileOpen}>{tr('跳至主内容')}</a>
    <div className="mobile-nav-backdrop" aria-hidden="true" onClick={closeNavigation} />
    <aside ref={sidebar} className="sidebar-v2" id="primary-navigation" inert={mobile && !mobileOpen} role={mobileOpen ? 'dialog' : undefined} aria-modal={mobileOpen || undefined} aria-label={tr('主导航')} onKeyDown={(event) => {
      if (!mobileOpen || event.key !== 'Tab') return
      const items = Array.from(sidebar.current?.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), input, select, [tabindex="0"]') || []).filter((item) => item.getClientRects().length > 0)
      const first = items[0], last = items[items.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
    }}>
      <div className="sidebar-brand-row">
        <Link to="/" className="brand-lockup"><div className="brand-symbol"><Waypoints size={20} /></div><div><strong>P2WLAN</strong><span>Control</span></div></Link>
        <IconButton className="sidebar-collapse" label={tr(sidebarCollapsed ? '展开导航' : '收起导航')} icon={sidebarCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />} aria-expanded={!sidebarCollapsed} onClick={() => setSidebarCollapsed((value) => !value)} />
        <button ref={navClose} type="button" className="icon-button-v2 sidebar-mobile-close" aria-label={tr('关闭导航')} onClick={closeNavigation}><X size={18} /></button>
      </div>
      <nav className="sidebar-nav" aria-label={tr('主导航')}>{navGroups.map((group) => <div className="nav-group" key={group.label}><span className="nav-group-label">{tr(group.label)}</span>{group.items.map((item) => <NavLink key={item.to} to={item.to} end={item.end} title={sidebarCollapsed ? tr(item.label) : undefined} aria-label={tr(item.label)} onClick={(event) => {
        if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
        setMobileOpen(false)
        // Focus the main region after React removes inert from the mobile content.
        window.requestAnimationFrame(() => main.current?.focus({ preventScroll: true }))
      }} aria-current={item.to === '/connections' && location.pathname === '/health' ? 'page' : undefined} className={({ isActive }) => `nav-link ${isActive || item.to === '/connections' && location.pathname === '/health' ? 'active' : ''}`}>{item.icon}<span>{tr(item.label)}</span></NavLink>)}</div>)}</nav>
      <div className="sidebar-runtime">
        <div className="runtime-line" title={runtimeLabel}><span className={`health-dot${runtimeSnapshot || runtime.isPending ? ' unknown' : ''}`} /><strong>{runtimeLabel}</strong><span className="sidebar-version">{runtime.data?.build_version ?? '—'}</span></div>
        {runtimeTime && <small>{tr('快照截至：')}<time dateTime={new Date(runtime.dataUpdatedAt).toISOString()}>{runtimeTime}</time></small>}
        {!refreshInterval && <small>{tr('自动刷新已关闭，可手动刷新。')}</small>}
        <div className="sidebar-account-row">
          <span className="sidebar-admin-copy"><strong>admin</strong><small>{tr('只读管理模式')}</small></span>
          <div className="sidebar-footer-actions"><ThemeSwitch /><ConsolePreferences onOpen={() => setSidebarCollapsed(false)} onLogout={() => { clearAdminToken(); queryClient.clear(); onLogout() }} /></div>
        </div>
      </div>
    </aside>
    <div className="app-main" inert={mobileOpen}>
      <header className="topbar-v2"><button ref={navTrigger} type="button" className="icon-button-v2 topbar-mobile-menu" aria-label={tr('打开导航')} aria-expanded={mobileOpen} aria-controls="primary-navigation" onClick={() => setMobileOpen(true)}><Menu size={18} /></button><div className="topbar-location"><span>P2WLAN Control</span><ChevronRight size={14} aria-hidden /><strong>{tr(meta.title)}</strong></div><div className="topbar-spacer" /><span className="topbar-readonly"><ShieldCheck size={15} aria-hidden />{tr('只读管理模式')}</span><IconButton label={tr('刷新数据')} disabled={refreshing} icon={<RefreshCw size={17} className={refreshing ? 'spin' : ''} />} onClick={refresh} /></header>
      <main ref={main} id="main-content" className="page-content" aria-labelledby="console-page-title" tabIndex={-1}><h1 id="console-page-title" className="sr-only">{tr(meta.title)}</h1><AsyncView key={location.pathname}><Outlet /></AsyncView></main>
    </div>
  </div>
}
