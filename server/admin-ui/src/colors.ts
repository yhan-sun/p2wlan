const ACCOUNT_COLORS = [
  '#2563eb', '#7c3aed', '#db2777', '#0891b2', '#059669', '#d97706',
  '#4f46e5', '#0f766e', '#9333ea', '#c2410c', '#0369a1', '#be123c',
]

export function accountColor(id?: string): string {
  if (!id) return '#64748b'
  let hash = 2166136261
  for (let i = 0; i < id.length; i += 1) {
    hash ^= id.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return ACCOUNT_COLORS[Math.abs(hash) % ACCOUNT_COLORS.length]
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
