const ACCOUNT_COLORS = [
  '#2563eb', '#7c3aed', '#0891b2', '#059669', '#d97706', '#db2777',
  '#4f46e5', '#0f766e', '#9333ea', '#c2410c', '#0369a1', '#be123c',
  '#1d4ed8', '#6d28d9', '#0e7490', '#047857', '#b45309', '#be185d',
  '#4338ca', '#115e59', '#7e22ce', '#9a3412', '#075985', '#9f1239',
]

function accountHash(id?: string): number {
  if (!id) return 0
  let hash = 2166136261
  for (let i = 0; i < id.length; i += 1) {
    hash ^= id.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return hash >>> 0
}

/**
 * Returns a stable, high-contrast account color. The palette is intentionally
 * bounded instead of generating arbitrary RGB values so labels remain legible
 * on both the topology canvas and white table surfaces.
 */
export function accountColor(id?: string): string {
  if (!id) return '#64748b'
  return ACCOUNT_COLORS[accountHash(id) % ACCOUNT_COLORS.length]
}

/**
 * Color is only the first identity channel: a finite accessible palette must
 * eventually repeat. This six-character code is a second stable visual key so
 * hundreds of accounts remain distinguishable even when two share a hue.
 */
export function accountIdentityCode(id?: string): string {
  if (!id) return '------'
  return accountHash(id).toString(36).toUpperCase().padStart(6, '0').slice(-6)
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
