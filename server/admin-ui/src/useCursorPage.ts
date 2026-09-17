import { useEffect, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import type { CursorPage } from './types'

export function useCursorPage<T>(
  queryKey: readonly unknown[],
  fetchPage: (cursor: string, signal?: AbortSignal) => Promise<CursorPage<T>>,
  resetToken: string,
) {
  const [cursor, setCursor] = useState('')
  const [history, setHistory] = useState<string[]>([])

  useEffect(() => {
    setCursor('')
    setHistory([])
  }, [resetToken])

  const query = useQuery({
    queryKey: [...queryKey, cursor],
    queryFn: ({ signal }) => fetchPage(cursor, signal),
    placeholderData: keepPreviousData,
  })

  const next = () => {
    const nextCursor = query.data?.next_cursor
    if (!nextCursor) return
    setHistory((current) => [...current, cursor])
    setCursor(nextCursor)
  }

  const previous = () => {
    setHistory((current) => {
      if (current.length === 0) return current
      const nextHistory = current.slice(0, -1)
      setCursor(current[current.length - 1])
      return nextHistory
    })
  }

  return {
    ...query,
    cursor,
    pageIndex: history.length,
    hasPrevious: history.length > 0,
    hasNext: Boolean(query.data?.next_cursor),
    next,
    previous,
  }
}
