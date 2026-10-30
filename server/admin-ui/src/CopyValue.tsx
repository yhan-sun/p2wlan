import { useEffect, useRef, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { tr } from './i18n'

export function CopyValue({ value, label = '复制', compact = false }: { value: string; label?: string; compact?: boolean }) {
  const [status, setStatus] = useState<'idle' | 'copied' | 'failed'>('idle')
  const revision = useRef(0)
  useEffect(() => {
    revision.current += 1
    setStatus('idle')
    return () => { revision.current += 1 }
  }, [value])
  const copy = async () => {
    const request = ++revision.current
    setStatus('idle')
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable')
      await navigator.clipboard.writeText(value)
      if (request === revision.current) setStatus('copied')
    } catch {
      if (request === revision.current) setStatus('failed')
    }
  }
  return <span className="copy-value">
    <button type="button" className={`copy-value-button${compact ? ' compact-copy' : ''}`} data-copy-state={status} onClick={() => { void copy() }} disabled={!value} aria-label={tr(label)} title={tr(status === 'copied' ? '已复制' : label)}>
      {status === 'copied' ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />}
      {!compact && <span>{tr(status === 'copied' ? '已复制' : label)}</span>}
    </button>
    <span className={`data-action-feedback${status !== 'failed' ? ' sr-only' : ''}`} role="status" aria-live="polite" aria-atomic="true">{status === 'failed' ? tr('复制失败，请手动选择文本。') : status === 'copied' ? `${tr(label)}: ${tr('已复制')}` : ''}</span>
    {status === 'failed' && <code className="copy-fallback-value" tabIndex={0}>{value}</code>}
  </span>
}
