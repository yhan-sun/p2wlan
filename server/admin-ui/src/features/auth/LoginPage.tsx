import { ArrowRight, CircleCheck, Eye, EyeOff, KeyRound, Waypoints } from 'lucide-react'
import { type FormEvent, useEffect, useRef, useState } from 'react'
import { LanguageSwitch, ThemeSwitch } from '../../ConsolePreferences'
import { ApiError, setAdminToken, verifyAdminToken } from '../../api'
import { tr } from '../../i18n'
export function LoginPage({ onSuccess }: { onSuccess: () => void }) {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [tokenVisible, setTokenVisible] = useState(false)
  const invalidToken = error === '管理员令牌至少需要 32 个字符。' || error === '管理员令牌无效。'
  const pendingLogin = useRef<AbortController | null>(null)
  useEffect(() => () => {
    const pending = pendingLogin.current
    pendingLogin.current = null
    pending?.abort()
  }, [])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (pendingLogin.current) return
    const normalized = token.trim()
    if (normalized.length < 32) {
      setError('管理员令牌至少需要 32 个字符。')
      return
    }
    const request = new AbortController()
    pendingLogin.current = request
    const timeout = window.setTimeout(() => request.abort(), 15_000)
    setSubmitting(true)
    setError('')
    try {
      await verifyAdminToken(normalized, request.signal)
      if (pendingLogin.current !== request) return
      if (request.signal.aborted) throw new DOMException('Login timed out', 'AbortError')
      setAdminToken(normalized)
      onSuccess()
    } catch (reason) {
      if (pendingLogin.current !== request) return
      if (request.signal.aborted) setError('验证超时，请检查网络连接后重试。')
      else if (reason instanceof ApiError && reason.status === 401) setError('管理员令牌无效。')
      else if (reason instanceof TypeError) setError('无法连接到控制面，请检查网络连接后重试。')
      else setError(reason instanceof Error ? reason.message : '无法连接到控制面。')
    } finally {
      window.clearTimeout(timeout)
      if (pendingLogin.current === request) {
        pendingLogin.current = null
        setSubmitting(false)
      }
    }
  }

  return <main className="login-page-v2">
    <section className="login-form-side">
      <form className="login-card-v2" onSubmit={submit} aria-busy={submitting}>
        <div className="login-language-row"><span className="sr-only">{tr('界面语言')}</span><div className="login-appearance-controls"><ThemeSwitch /><LanguageSwitch /></div></div>
        <div className="login-brand"><div className="brand-symbol"><Waypoints size={24} /></div><strong>P2WLAN <span>Control</span></strong></div>
        <h1>{tr("登录控制台")}</h1>
        <p>{tr("使用管理员令牌，查看资源与连接状态。")}</p>
        <label htmlFor="admin-token">{tr("管理员令牌")}</label>
        <div className="input-with-icon"><KeyRound size={16} /><input id="admin-token" type={tokenVisible ? "text" : "password"} readOnly={submitting} aria-invalid={invalidToken} aria-describedby="admin-token-help admin-token-error" spellCheck={false} value={token} onChange={(event) => { setToken(event.target.value); setError('') }} placeholder={tr("至少 32 个字符")} autoComplete="current-password" autoFocus /><button type="button" className="token-visibility-button" aria-label={tr(tokenVisible ? "隐藏令牌" : "显示令牌")} aria-pressed={tokenVisible} onClick={() => setTokenVisible((value) => !value)}>{tokenVisible ? <EyeOff size={16} /> : <Eye size={16} />}</button></div>
        <p id="admin-token-help" className="login-token-help">{tr("输入部署时配置的 ")}<code>CONTROL_ADMIN_TOKEN</code>{tr("。")}</p>
        <div id="admin-token-error" role="status" aria-live="polite" className={`login-error ${error ? 'visible' : ''}`}>{tr(error) || ' '}</div>
        <button className="button primary login-button" type="submit" disabled={submitting}>{submitting ? <><div className="spinner light" />{tr("验证中…")}</> : <>{tr("进入控制台")}<ArrowRight size={16} /></>}</button>
        <div className="session-note"><CircleCheck size={14} />{tr("令牌仅保存在当前标签页会话中")}</div>
      </form>
    </section>
  </main>
}
