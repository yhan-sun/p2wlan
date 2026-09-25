export interface DagreBox {
  id: string
  width: number
  height: number
  point: { x: number; y: number }
}

/**
 * Dagre can legally collapse sibling nodes onto the same coordinates when
 * several peers share identical predecessors/successors. React Flow then
 * renders those cards on top of one another. Preserve Dagre's horizontal
 * ranks, but deterministically spread only ranks whose vertical boxes overlap.
 */
export function spreadDagreRankCollisions(
  boxes: DagreBox[],
  gap = 36,
): Map<string, { x: number; y: number }> {
  const placements = new Map<string, { x: number; y: number }>()
  const ranks = new Map<number, DagreBox[]>()

  for (const box of boxes) {
    const rank = Math.round(box.point.x / 8) * 8
    const items = ranks.get(rank) ?? []
    items.push(box)
    ranks.set(rank, items)
  }

  for (const items of ranks.values()) {
    const ordered = [...items].sort((a, b) =>
      a.point.y - b.point.y || a.id.localeCompare(b.id),
    )

    let overlaps = false
    for (let index = 1; index < ordered.length; index += 1) {
      const previous = ordered[index - 1]
      const current = ordered[index]
      const previousBottom = previous.point.y + previous.height / 2
      const currentTop = current.point.y - current.height / 2
      if (currentTop < previousBottom + gap) {
        overlaps = true
        break
      }
    }

    if (!overlaps) {
      for (const box of ordered) placements.set(box.id, box.point)
      continue
    }

    const centerY = ordered.reduce((sum, box) => sum + box.point.y, 0) / ordered.length
    const totalHeight = ordered.reduce((sum, box) => sum + box.height, 0)
      + gap * Math.max(0, ordered.length - 1)

    let cursor = centerY - totalHeight / 2
    for (const box of ordered) {
      const y = cursor + box.height / 2
      placements.set(box.id, { x: box.point.x, y })
      cursor += box.height + gap
    }
  }

  return placements
}
