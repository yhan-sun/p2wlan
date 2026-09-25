import { type FormEvent, useState } from 'react'
import { ArrowRight, CircleCheck, KeyRound, ShieldCheck, Waypoints } from 'lucide-react'
import { ApiError, setAdminToken, verifyAdminToken } from '../../api'

export function Login({ onSuccess }: { onSuccess: () => void }) {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    const normalized = token.trim()
    if (normalized.length < 32) {
      setError('管理员令牌至少需要 32 个字符。')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      await verifyAdminToken(normalized)
      setAdminToken(normalized)
      onSuccess()
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) setError('管理员令牌无效。')
      else setError(reason instanceof Error ? reason.message : '无法连接到 Control。')
    } finally {
      setSubmitting(false)
    }
  }

  return <main className="login-page-v2">
    <section className="login-brand-side">
      <div className="brand-lockup large"><div className="brand-symbol"><Waypoints size={22} /></div><div><strong>P2WLAN</strong><span>控制平面</span></div></div>
      <div className="login-brand-copy"><span className="eyebrow-v2">自托管控制平面</span><h1>资源关系和真实路径，<br />各自说清楚。</h1><p>Control 资源关系与 daemon 权威连接观测分开呈现，保持只读运维边界。</p></div>
      <div className="login-security"><ShieldCheck size={17} /><span>管理权限与用户 JWT / 设备凭据完全隔离</span></div>
    </section>
    <section className="login-form-side">
      <form className="login-card-v2" onSubmit={submit}>
        <div className="mobile-brand"><div className="brand-symbol"><Waypoints size={20} /></div><strong>P2WLAN 控制台</strong></div>
        <span className="eyebrow-v2">管理控制台</span>
        <h2>登录控制台</h2>
        <p>输入部署时配置的 <code>CONTROL_ADMIN_TOKEN</code>。</p>
        <label htmlFor="admin-token">管理员令牌</label>
        <div className="input-with-icon"><KeyRound size={16} /><input id="admin-token" type="password" value={token} onChange={(event) => setToken(event.target.value)} placeholder="至少 32 个字符" autoComplete="current-password" autoFocus /></div>
        <div className={`login-error ${error ? 'visible' : ''}`}>{error || ' '}</div>
        <button className="button primary login-button" type="submit" disabled={submitting}>{submitting ? <><div className="spinner light" />验证中…</> : <>进入控制台<ArrowRight size={16} /></>}</button>
        <div className="session-note"><CircleCheck size={14} />令牌仅保存在当前标签页会话中</div>
      </form>
    </section>
  </main>
}
