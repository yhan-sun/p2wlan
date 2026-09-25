import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  Gauge,
  LayoutDashboard,
  LogOut,
  Menu,
  MonitorSmartphone,
  Moon,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  RadioTower,
  RefreshCw,
  Sun,
  Users,
  Waypoints,
} from 'lucide-react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { adminApi, clearAdminToken } from '../api'
import { applyTheme, nextThemeMode, readThemeMode, resolveTheme, writeThemeMode, type ThemeMode } from '../shared/theme'
import { IconButton } from '../components/ui/console'

const navGroups = [
  { label: '工作台', items: [
    { to: '/', end: true, icon: <LayoutDashboard size={17} />, label: '概览' },
    { to: '/accounts', icon: <Users size={17} />, label: '账号' },
  ] },
  { label: '网络', items: [
    { to: '/devices', icon: <MonitorSmartphone size={17} />, label: '设备' },
    { to: '/networks', icon: <Network size={17} />, label: '网络与房间' },
    { to: '/connections', icon: <RadioTower size={17} />, label: '连接路径' },
    { to: '/relationships', icon: <Waypoints size={17} />, label: '资源关系' },
  ] },
  { label: '可观测性', items: [
    { to: '/health', icon: <Gauge size={17} />, label: '连接健康' },
    { to: '/system', icon: <Activity size={17} />, label: '运行健康' },
  ] },
]

function pageMeta(pathname: string): { title: string; eyebrow: string } {
  if (pathname.startsWith('/accounts/')) return { title: '账号详情', eyebrow: '账号' }
  if (pathname === '/accounts') return { title: '账号', eyebrow: '账号' }
  if (pathname === '/relationships') return { title: '资源关系', eyebrow: '资源关系' }
  if (pathname === '/connections') return { title: '连接路径', eyebrow: '网络' }
  if (pathname === '/devices') return { title: '设备', eyebrow: '设备' }
  if (pathname === '/networks') return { title: '网络与房间', eyebrow: '网络' }
  if (pathname === '/health') return { title: '连接健康', eyebrow: '可观测性' }
  if (pathname === '/system') return { title: '运行健康', eyebrow: '可观测性' }
  return { title: '概览', eyebrow: '总览' }
}

export function Shell({ onLogout }: { onLogout: () => void }) {
  const location = useLocation()
  const meta = pageMeta(location.pathname)
  const queryClient = useQueryClient()
  const runtime = useQuery({ queryKey: ['runtime-shell'], queryFn: adminApi.runtime, refetchInterval: 60_000 })
  const [refreshing, setRefreshing] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [themeMode, setThemeMode] = useState<ThemeMode>(readThemeMode)

  useEffect(() => {
    writeThemeMode(themeMode)
    if (themeMode !== 'system') return
    const query = window.matchMedia('(prefers-color-scheme: dark)')
    const sync = () => applyTheme('system')
    query.addEventListener('change', sync)
    return () => query.removeEventListener('change', sync)
  }, [themeMode])

  useEffect(() => {
    setMobileOpen(false)
  }, [location.pathname])

  const refresh = async () => {
    setRefreshing(true)
    try { await queryClient.invalidateQueries() } finally { window.setTimeout(() => setRefreshing(false), 250) }
  }

  const layoutClass = [
    'app-layout',
    sidebarCollapsed ? 'sidebar-collapsed' : '',
    mobileOpen ? 'mobile-nav-open' : '',
  ].filter(Boolean).join(' ')

  return <div className={layoutClass}>
    <button
      className="mobile-nav-backdrop"
      aria-label="关闭导航"
      onClick={() => setMobileOpen(false)}
    />
    <aside className="sidebar-v2" id="primary-navigation">
      <div className="sidebar-brand-row">
        <Link to="/" className="brand-lockup">
          <div className="brand-symbol"><Waypoints size={20} /></div>
          <div><strong>P2WLAN</strong><span>控制平面</span></div>
        </Link>
        <IconButton
          className="sidebar-collapse"
          label={sidebarCollapsed ? '展开导航' : '收起导航'}
          icon={sidebarCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          onClick={() => setSidebarCollapsed((value) => !value)}
        />
      </div>
      <nav className="sidebar-nav">
        {navGroups.map((group) => <div className="nav-group" key={group.label}>
          <span className="nav-group-label">{group.label}</span>
          {group.items.map((item) => <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            title={sidebarCollapsed ? item.label : undefined}
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
          >
            {item.icon}<span>{item.label}</span>
          </NavLink>)}
        </div>)}
      </nav>
      <div className="sidebar-runtime">
        <div className="runtime-line">
          <span className={`health-dot${runtime.isError ? ' down' : runtime.isPending ? ' unknown' : ''}`} />
          <strong>{runtime.isError ? 'Control 不可达' : runtime.isPending ? '正在检查 Control' : 'Control 正常'}</strong>
        </div>
        <span>{runtime.data?.build_version ?? (runtime.isError ? '—' : 'loading…')}</span>
        <small>只读管理模式</small>
      </div>
    </aside>
    <div className="app-main">
      <header className="topbar-v2">
        <IconButton
          className="topbar-mobile-menu"
          label="打开导航"
          icon={<Menu size={18} />}
          onClick={() => setMobileOpen(true)}
        />
        <div className="topbar-context">
          <span className="topbar-eyebrow">{meta.eyebrow}</span>
          <h1>{meta.title}</h1>
        </div>
        <div className="topbar-actions-v2">
          <IconButton
            label={themeMode === 'system' ? '主题：跟随系统' : themeMode === 'light' ? '主题：浅色' : '主题：深色'}
            icon={themeMode === 'system'
              ? <MonitorSmartphone size={17} />
              : resolveTheme(themeMode) === 'dark'
                ? <Moon size={17} />
                : <Sun size={17} />}
            onClick={() => setThemeMode((value) => nextThemeMode(value))}
          />
          <IconButton
            label="刷新数据"
            icon={<RefreshCw size={17} className={refreshing ? 'spin' : ''} />}
            onClick={refresh}
          />
          <div className="topbar-divider" />
          <button
            className="user-menu-button"
            onClick={() => { clearAdminToken(); queryClient.clear(); onLogout() }}
          >
            <span className="user-avatar">AD</span>
            <span className="user-menu-copy"><strong>admin</strong><small>只读</small></span>
            <LogOut size={15} />
          </button>
        </div>
      </header>
      <main className="page-content"><Outlet /></main>
    </div>
  </div>
}
