import { Component, Suspense, type ReactNode } from 'react'
import { CircleAlert } from 'lucide-react'
import { tr } from './i18n'

class ViewBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  render() {
    if (this.state.failed) return <div className="error-block" role="alert">
      <CircleAlert size={18} />
      <div><strong>{tr('视图加载失败')}</strong><button className="button secondary compact" onClick={() => window.location.reload()}>{tr('重新加载页面')}</button></div>
    </div>
    return this.props.children
  }
}

export function AsyncView({ children }: { children: ReactNode }) {
  return <ViewBoundary><Suspense fallback={<div className="loading-block" role="status"><div className="spinner" />{tr('正在加载视图…')}</div>}>
    {children}
  </Suspense></ViewBoundary>
}
