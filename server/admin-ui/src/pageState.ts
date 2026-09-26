import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'

export function withPageParams(params: URLSearchParams, patch: Record<string, string>) {
  const next = new URLSearchParams(params)
  for (const [key, value] of Object.entries(patch)) {
    if (value) next.set(key, value)
    else next.delete(key)
  }
  return next
}

export function usePageState() {
  const [params, setParams] = useSearchParams()
  const update = (patch: Record<string, string>, replace = false) => {
    setParams((current) => withPageParams(current, patch), { replace })
  }
  return { params, update }
}

// Keep a bounded previous-page trail in browser history state, not in a growing URL.
// A shared deep link has no trail; its previous action explicitly returns to page one.
export function useCursorPage() {
  const [params] = useSearchParams()
  const location = useLocation()
  const navigate = useNavigate()
  const cursor = params.get('cursor') || ''
  const parsed = Number(params.get('page'))
  const pageIndex = cursor && Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 0
  const rawHistory: unknown = location.state?.cursorHistory
  const history: string[] = Array.isArray(rawHistory) && rawHistory.every((value) => typeof value === 'string') ? rawHistory.slice(-100) : []
  const move = (nextCursor: string, page: number, trail: string[]) => {
    navigate({ pathname: location.pathname, search: withPageParams(params, { cursor: nextCursor, page: nextCursor ? String(page) : '' }).toString() }, { state: { cursorHistory: trail } })
  }
  return {
    cursor, pageIndex,
    canPrev: Boolean(cursor),
    previousIsFirst: Boolean(cursor) && !history.length,
    next: (nextCursor: string) => { if (nextCursor) move(nextCursor, pageIndex + 1, [...history, cursor].slice(-100)) },
    prev: () => move(history.at(-1) ?? '', Math.max(0, pageIndex - 1), history.slice(0, -1)),
  }
}

export function connectionLink(scope: { deviceId?: string; accountId?: string; networkId?: string }) {
  const params = new URLSearchParams()
  if (scope.deviceId) params.set('device_id', scope.deviceId)
  if (scope.accountId) params.set('account_id', scope.accountId)
  if (scope.networkId) params.set('network_id', scope.networkId)
  return `/connections?${params}`
}

export function relationshipLink(networkId: string, accountId?: string) {
  const params = new URLSearchParams()
  if (networkId === 'default' && accountId) params.set('network_id', `personal:${accountId}`)
  else if (networkId !== 'default') params.set('network_id', networkId)
  if (accountId) params.set('account_id', accountId)
  return `/relationships?${params}`
}
