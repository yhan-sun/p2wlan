import type { AdminTopologyPage } from './types'

export function mergeTopologyPages(pages: AdminTopologyPage[]): AdminTopologyPage | undefined {
  if (pages.length === 0) return undefined

  const nodes = new Map<string, AdminTopologyPage['nodes'][number]>()
  const edges = new Map<string, AdminTopologyPage['edges'][number]>()
  let generatedAt = 0
  let loadedAccounts = 0
  let partial = false
  let partialReason = ''

  for (const page of pages) {
    generatedAt = Math.max(generatedAt, page.generated_at)
    loadedAccounts += page.loaded_accounts
    if (page.partial) {
      partial = true
      partialReason ||= page.partial_reason || 'budget'
    }
    for (const node of page.nodes) nodes.set(node.id, node)
    for (const edge of page.edges) edges.set(edge.id, edge)
  }

  const last = pages[pages.length - 1]
  const first = pages[0]
  return {
    ...last,
    generated_at: generatedAt,
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    loaded_accounts: loadedAccounts,
    total_accounts: first.total_accounts,
    partial,
    partial_reason: partialReason || undefined,
    complete: !partial && last.complete,
  }
}
