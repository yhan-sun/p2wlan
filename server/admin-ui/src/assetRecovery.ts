const RECOVERY_KEY = 'p2wlan-admin-asset-recovery'
const RECOVERY_WINDOW_MS = 60_000

interface RecoveryEnvironment {
  storage: Pick<Storage, 'getItem' | 'setItem'>
  reload: () => void
  now: number
  online: boolean
}

/** One automatic reload per tab/minute; storage failure must never create a loop. */
export function recoverAssetLoad({ storage, reload, now, online }: RecoveryEnvironment): boolean {
  if (!online) return false
  try {
    const previous = Number(storage.getItem(RECOVERY_KEY))
    if (Number.isFinite(previous) && previous > 0 && now >= previous && now - previous < RECOVERY_WINDOW_MS) return false
    storage.setItem(RECOVERY_KEY, String(now))
  } catch { return false }
  // reload retains the exact URL, history state and admin sessionStorage token.
  reload()
  return true
}

export function installAssetRecovery() {
  window.addEventListener('vite:preloadError', (event) => {
    let recovered = false
    try {
      recovered = recoverAssetLoad({ storage: window.sessionStorage, reload: () => window.location.reload(), now: Date.now(), online: navigator.onLine })
    } catch { /* The view boundary remains available when session storage is blocked. */ }
    if (recovered) event.preventDefault()
  })
}
