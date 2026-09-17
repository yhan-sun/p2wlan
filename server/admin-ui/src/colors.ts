const ACCOUNT_COLORS = [
  '#2563eb', '#7c3aed', '#0891b2', '#059669', '#d97706', '#db2777',
  '#4f46e5', '#0f766e', '#9333ea', '#c2410c', '#0369a1', '#be123c',
  '#1d4ed8', '#6d28d9', '#0e7490', '#047857', '#b45309', '#be185d',
  '#4338ca', '#115e59', '#7e22ce', '#9a3412', '#075985', '#9f1239',
]

/**
 * Returns a stable, high-contrast account color. The palette is intentionally
 * bounded instead of generating arbitrary RGB values so labels remain legible
 * on both the topology canvas and white table surfaces.
 */
function accountHash(id?: string): number {
  if (!id) return 0
  let hash = 2166136261
  for (let i = 0; i < id.length; i += 1) {
    hash ^= id.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return hash >>> 0
}

export function accountColor(id?: string): string {
  if (!id) return '#64748b'
  return ACCOUNT_COLORS[accountHash(id) % ACCOUNT_COLORS.length]
}

export function accountIdentity(id?: string): { color: string; code: string } {
  if (!id) return { color: '#64748b', code: '--' }
  const hash = accountHash(id)
  // Color is intentionally bounded for contrast. The independent six-character base36 code
  // is the second visual channel, so two accounts that share one of the 24
  // colors are still distinguishable in the graph and legend.
  const code = (hash % 2176782336).toString(36).toUpperCase().padStart(6, '0')
  return { color: ACCOUNT_COLORS[hash % ACCOUNT_COLORS.length], code }
}

export function colorWithAlpha(hex: string, alpha: number): string {
  const normalized = hex.replace('#', '')
  if (normalized.length !== 6) return hex
  const value = Number.parseInt(normalized, 16)
  const r = (value >> 16) & 255
  const g = (value >> 8) & 255
  const b = value & 255
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}
