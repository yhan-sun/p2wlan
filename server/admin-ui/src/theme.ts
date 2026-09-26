import { useSyncExternalStore } from 'react'

export type AdminTheme = 'light' | 'dark'

const STORAGE_KEY = 'p2wlan-admin-theme'
const listeners = new Set<() => void>()

function readInitialTheme(): AdminTheme {
  if (typeof window === 'undefined') return 'light'
  return window.localStorage.getItem(STORAGE_KEY) === 'dark' ? 'dark' : 'light'
}

let activeTheme: AdminTheme = readInitialTheme()

function applyTheme(theme: AdminTheme) {
  if (typeof document !== 'undefined') document.documentElement.dataset.theme = theme
}

applyTheme(activeTheme)

function subscribe(listener: () => void) {
  listeners.add(listener)
  const onStorage = (event: StorageEvent) => {
    if (event.key !== STORAGE_KEY) return
    activeTheme = event.newValue === 'dark' ? 'dark' : 'light'
    applyTheme(activeTheme)
    for (const subscriber of listeners) subscriber()
  }
  window.addEventListener('storage', onStorage)
  return () => {
    listeners.delete(listener)
    window.removeEventListener('storage', onStorage)
  }
}

export function getTheme(): AdminTheme {
  return activeTheme
}

export function setTheme(theme: AdminTheme) {
  if (theme === activeTheme) return
  activeTheme = theme
  if (typeof window !== 'undefined') window.localStorage.setItem(STORAGE_KEY, theme)
  applyTheme(theme)
  for (const listener of listeners) listener()
}

export function useTheme(): AdminTheme {
  return useSyncExternalStore(subscribe, getTheme, () => 'light')
}
