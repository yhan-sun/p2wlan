import type { ButtonHTMLAttributes, ReactNode } from 'react'

type PanelProps = {
  title?: string
  subtitle?: string
  action?: ReactNode
  className?: string
  children: ReactNode
}

export function Panel({ title, subtitle, action, className = '', children }: PanelProps) {
  return <section className={`panel-v2 ${className}`}>
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
