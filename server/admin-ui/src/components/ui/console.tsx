import { useEffect, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { X } from 'lucide-react'

type PanelProps = {
  title?: string
  subtitle?: string
  action?: ReactNode
  className?: string
  children: ReactNode
}

export function Panel({ title, subtitle, action, className = '', children }: PanelProps) {
  return <section className={`panel-v2 ${className}`.trim()}>
    {(title || action) && <header className="panel-v2-header">
      <div>
        {title && <h2>{title}</h2>}
        {subtitle && <p>{subtitle}</p>}
      </div>
      {action}
    </header>}
    {children}
  </section>
}

type MetricCardProps = {
  icon: ReactNode
  label: string
  value: ReactNode
  meta: ReactNode
}

export function MetricCard({ icon, label, value, meta }: MetricCardProps) {
  return <article className="metric-card-v2">
    <div className="metric-icon">{icon}</div>
    <div className="metric-copy">
      <span>{label}</span>
      <strong>{value}</strong>
      <p>{meta}</p>
    </div>
  </article>
}

type IconButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  label: string
  icon: ReactNode
}

export function IconButton({ label, icon, className = '', ...props }: IconButtonProps) {
  return <button
    type="button"
    className={`icon-button-v2 ${className}`.trim()}
    aria-label={label}
    title={label}
    {...props}
  >
    {icon}
  </button>
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string
  title: string
  description?: ReactNode
  actions?: ReactNode
}) {
  return <header className="console-page-header">
    <div className="console-page-heading">
      {eyebrow && <span className="console-page-eyebrow">{eyebrow}</span>}
      <h2>{title}</h2>
      {description && <p>{description}</p>}
    </div>
    {actions && <div className="console-page-actions">{actions}</div>}
  </header>
}

export function SegmentedControl<T extends string | number>({
  value,
  options,
  onChange,
  label,
}: {
  value: T
  options: readonly { label: string; value: T; icon?: ReactNode }[]
  onChange: (value: T) => void
  label: string
}) {
  return <div className="console-segmented" role="group" aria-label={label}>
    {options.map((option) => <button
      type="button"
      key={String(option.value)}
      className={value === option.value ? 'active' : ''}
      aria-pressed={value === option.value}
      onClick={() => onChange(option.value)}
    >
      {option.icon}{option.label}
    </button>)}
  </div>
}

export function StatusPill({
  children,
  tone = 'neutral',
  dot = false,
}: {
  children: ReactNode
  tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'accent'
  dot?: boolean
}) {
  return <span className={`console-status-pill ${tone}`}>
    {dot && <span className="console-status-dot" />}
    {children}
  </span>
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode
  title: string
  description?: ReactNode
  action?: ReactNode
}) {
  return <div className="console-empty-state">
    {icon && <span className="console-empty-icon">{icon}</span>}
    <div><strong>{title}</strong>{description && <p>{description}</p>}</div>
    {action}
  </div>
}

export function Sheet({
  title,
  description,
  onClose,
  children,
  width = 'wide',
}: {
  title: ReactNode
  description?: ReactNode
  onClose: () => void
  children: ReactNode
  width?: 'normal' | 'wide'
}) {
  useEffect(() => {
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', close)
    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('keydown', close)
    }
  }, [onClose])

  return <>
    <button className="console-sheet-backdrop" aria-label="关闭详情" onClick={onClose} />
    <aside className={`console-sheet ${width}`} aria-label="详情">
      <header className="console-sheet-header">
        <div>
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        <IconButton label="关闭详情" icon={<X size={17} />} onClick={onClose} />
      </header>
      <div className="console-sheet-body">{children}</div>
    </aside>
  </>
}
