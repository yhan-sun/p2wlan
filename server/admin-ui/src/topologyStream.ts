import { useEffect, useMemo } from 'react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { adminApi } from './api'
import type { AdminTopology, AdminTopologyEdge, AdminTopologyPage, TopologyView } from './types'

function mergeSignalEdge(current: AdminTopologyEdge | undefined, incoming: AdminTopologyEdge): AdminTopologyEdge {
  if (!current) {
    return {
      ...incoming,
      id: `signal:${incoming.source}:${incoming.target}:${incoming.signal_type || 'signal'}`,
    }
  }
  return {
    ...current,
    count: (current.count || 0) + (incoming.count || 0),
    created_at: Math.max(current.created_at || 0, incoming.created_at || 0),
  }
}

export function mergeTopologyPages(pages: AdminTopologyPage[]): AdminTopology | undefined {
  const first = pages[0]
  if (!first) return undefined
  const nodes = new Map<string, AdminTopology['nodes'][number]>()
  const edges = new Map<string, AdminTopologyEdge>()

  for (const page of pages) {
    for (const node of page.nodes) nodes.set(node.id, node)
    for (const edge of page.edges) {
      if (edge.kind === 'pending_signal') {
        const key = `signal:${edge.source}:${edge.target}:${edge.signal_type || 'signal'}`
        edges.set(key, mergeSignalEdge(edges.get(key), edge))
      } else {
        edges.set(edge.id, edge)
      }
    }
  }
  const last = pages[pages.length - 1]
  return {
    generated_at: last.generated_at,
    snapshot_at: first.snapshot_at,
    scope: first.scope,
    view: first.view,
    focus_account_id: first.focus_account_id,
    path_observation_available: first.path_observation_available,
    path_observation_note: first.path_observation_note,
    complete: Boolean(last.complete),
    nodes: Array.from(nodes.values()),
    edges: Array.from(edges.values()),
  }
}

export function useTopologyStream(accountId: string, view: TopologyView, enabled = true) {
  const account = accountId || undefined
  const query = useInfiniteQuery({
    queryKey: ['topology-stream', accountId || 'global', view],
    queryFn: ({ pageParam, signal }) => adminApi.topologyPage(account, view, pageParam, 100, signal),
    initialPageParam: '',
    getNextPageParam: (lastPage) => lastPage.next_cursor || undefined,
    enabled,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  })

  // Continue a snapshot until its explicit completion marker. Each request is
  // bounded to 100 source records and React Query aborts the active fetch when
  // the scope/view is replaced, so switching accounts cannot leave an
  // unbounded background crawl behind.
  useEffect(() => {
    if (!enabled || !query.hasNextPage || query.isFetchingNextPage || query.isError) return
    void query.fetchNextPage()
  }, [enabled, query.hasNextPage, query.isFetchingNextPage, query.isError, query.data?.pages.length, query.fetchNextPage])

  const data = useMemo(() => mergeTopologyPages(query.data?.pages ?? []), [query.data?.pages])
  return {
    data,
    error: query.error,
    isPending: query.isPending,
    fetchStatus: query.fetchStatus,
    streaming: Boolean(query.hasNextPage || query.isFetchingNextPage),
    refetch: query.refetch,
  }
}
