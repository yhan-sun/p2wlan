import { useEffect, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import type { CursorPage } from './types'

interface CursorState {
  token: string
  cursor: string
  history: string[]
}

export function useCursorPage<T>(
  queryKey: readonly unknown[],
  fetchPage: (cursor: string, signal?: AbortSignal) => Promise<CursorPage<T>>,
  resetToken: string,
) {
  const [state, setState] = useState<CursorState>({ token: resetToken, cursor: '', history: [] })
  const effective = state.token === resetToken
    ? state
    : { token: resetToken, cursor: '', history: [] }

  // Effects run after a render; deriving effective state above ensures that a
  // changed filter never sends the previous filter's opaque cursor during that
  // transition frame.
  useEffect(() => {
    if (state.token === resetToken) return
    setState({ token: resetToken, cursor: '', history: [] })
  }, [resetToken, state.token])

  const query = useQuery({
    queryKey: [...queryKey, effective.cursor],
    queryFn: ({ signal }) => fetchPage(effective.cursor, signal),
    placeholderData: keepPreviousData,
  })

  const next = () => {
    const nextCursor = query.data?.next_cursor
    if (!nextCursor) return
    setState((current) => {
      const base = current.token === resetToken ? current : { token: resetToken, cursor: '', history: [] }
      return { token: resetToken, cursor: nextCursor, history: [...base.history, base.cursor] }
    })
  }

  const previous = () => {
    setState((current) => {
      const base = current.token === resetToken ? current : { token: resetToken, cursor: '', history: [] }
      if (base.history.length === 0) return base
      return {
        token: resetToken,
        cursor: base.history[base.history.length - 1],
        history: base.history.slice(0, -1),
      }
    })
  }

  return {
    ...query,
    cursor: effective.cursor,
    pageIndex: effective.history.length,
    hasPrevious: effective.history.length > 0,
    hasNext: Boolean(query.data?.next_cursor),
    next,
    previous,
  }
}
