import { type ReactNode, useEffect, useId, useRef, useState } from 'react'
import { LogOut, Monitor, Moon, Settings2, Sun, X } from 'lucide-react'
import { setLocale, tr, useLocale } from './i18n'
import { setTheme, useTheme } from './theme'
import { DensityToggle } from './density'
import { RefreshToggle } from './refresh'
import { useOverlay } from './useOverlay'

export function LanguageSwitch() {
  const locale = useLocale()
  return <div className="locale-switch" role="group" aria-label={tr('界面语言')}>
    <button type="button" className={locale === 'zh-CN' ? 'active' : ''} aria-pressed={locale === 'zh-CN'} title={tr('简体中文')} onClick={() => setLocale('zh-CN')}>中</button>
    <button type="button" className={locale === 'en-US' ? 'active' : ''} aria-pressed={locale === 'en-US'} title="English" onClick={() => setLocale('en-US')}>EN</button>
  </div>
}

export function ThemeSwitch() {
  const theme = useTheme()
  const label = tr(theme === 'system' ? '主题：跟随系统' : theme === 'light' ? '主题：浅色' : '主题：深色')
  const next = theme === 'system' ? 'light' : theme === 'light' ? 'dark' : 'system'
  return <button type="button" className="theme-switch" onClick={() => setTheme(next)} title={label} aria-label={label}>
    {theme === 'system' ? <Monitor size={16} /> : theme === 'light' ? <Sun size={16} /> : <Moon size={16} />}
  </button>
}

function PreferenceRow({ label, children }: { label: string; children: ReactNode }) {
  return <div className="console-preference-row"><span>{tr(label)}</span>{children}</div>
}

export function ConsolePreferences({ onLogout, onOpen, showLabel = false }: { onLogout: () => void; onOpen?: () => void; showLabel?: boolean }) {
  const theme = useTheme()
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  const panelId = useId()
  const close = () => { setOpen(false); trigger.current?.focus() }
  useOverlay(open, close, { lockScroll: false })
  useEffect(() => {
    if (!open) return
    closeButton.current?.focus()
    const outside = (event: PointerEvent) => {
      if (event.target instanceof Node && !root.current?.contains(event.target)) setOpen(false)
    }
    document.addEventListener('pointerdown', outside)
    return () => document.removeEventListener('pointerdown', outside)
  }, [open])
  return <div className="console-preferences" ref={root} onBlur={(event) => {
    if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) setOpen(false)
  }}>
    <button ref={trigger} type="button" className={`icon-button-v2${showLabel ? ' preferences-with-label' : ''}`} title={tr('控制台偏好')} aria-label={tr(showLabel ? '偏好设置' : '控制台偏好')} aria-expanded={open} aria-controls={panelId} aria-haspopup="dialog" onClick={() => { if (!open) onOpen?.(); setOpen((value) => !value) }}><Settings2 size={16} />{showLabel && <span>{tr('偏好设置')}</span>}</button>
    {open && <section id={panelId} className="console-preferences-panel" role="dialog" aria-label={tr('控制台偏好')}>
      <header><strong>{tr('控制台偏好')}</strong><button ref={closeButton} type="button" className="icon-button-v2" aria-label={tr('关闭偏好')} onClick={close}><X size={16} /></button></header>
      <RefreshToggle />
      <PreferenceRow label="界面主题"><select className="select-field theme-select" aria-label={tr('界面主题')} value={theme} onChange={(event) => setTheme(event.target.value as 'system' | 'light' | 'dark')}><option value="system">{tr('跟随系统')}</option><option value="light">{tr('浅色')}</option><option value="dark">{tr('深色')}</option></select></PreferenceRow>
      <PreferenceRow label="界面语言"><LanguageSwitch /></PreferenceRow>
      <div className="console-preference-row"><DensityToggle /></div>
      <footer><span>{tr('只读管理模式')}</span><button type="button" className="button secondary compact" onClick={onLogout}><LogOut size={15} />{tr('退出登录')}</button></footer>
    </section>}
  </div>
}
