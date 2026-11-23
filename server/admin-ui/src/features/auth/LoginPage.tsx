import { ArrowRight, CircleCheck, Eye, EyeOff, KeyRound, UserRound, Waypoints } from 'lucide-react'
import { type FormEvent, useEffect, useRef, useState } from 'react'
import { LanguageSwitch, ThemeSwitch } from '../../ConsolePreferences'
import { ApiError, openAdminSession, setAdminToken, supportsPasswordLogin, verifyAdminToken } from '../../api'
import { tr } from '../../i18n'
export function LoginPage({ onSuccess }: { onSuccess: () => void }) {
  const [credential, setCredential] = useState('')
  const [username, setUsername] = useState('')
  const [passwordAvailable, setPasswordAvailable] = useState(false)
  const [method, setMethod] = useState<'loading' | 'password' | 'token'>('loading')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [visible, setVisible] = useState(false)
  const account = method === 'password'
  const invalidCredential = error === '管理员令牌至少需要 32 个字符。' || error === '管理员令牌无效。' || error === '管理员账号或密码不正确。'
  const pendingLogin = useRef<AbortController | null>(null)
  useEffect(() => {
    const request = new AbortController()
    let active = true
    const timeout = window.setTimeout(() => request.abort(), 5000)
    supportsPasswordLogin(request.signal).catch(() => false).then(available => {
      if (active) {
        setPasswordAvailable(available)
        setMethod(available ? 'password' : 'token')
      }
    }).finally(() => window.clearTimeout(timeout))
    return () => { active = false; request.abort(); window.clearTimeout(timeout) }
  }, [])
  useEffect(() => () => {
    const pending = pendingLogin.current
    pendingLogin.current = null
    pending?.abort()
  }, [])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (pendingLogin.current || method === 'loading') return
    const normalized = credential.trim()
    if (!account && normalized.length < 32) {
      setError('管理员令牌至少需要 32 个字符。')
      return
    }
    const request = new AbortController()
    pendingLogin.current = request
    const timeout = window.setTimeout(() => request.abort(), 15_000)
    setSubmitting(true)
    setError('')
    try {
      let session = normalized
      if (account) session = await openAdminSession(username, credential, request.signal)
      else await verifyAdminToken(normalized, request.signal)
      if (pendingLogin.current !== request) return
      if (request.signal.aborted) throw new DOMException('Login timed out', 'AbortError')
      setAdminToken(session)
      onSuccess()
    } catch (reason) {
      if (pendingLogin.current !== request) return
      if (request.signal.aborted) setError('验证超时，请检查网络连接后重试。')
      else if (reason instanceof ApiError && reason.status === 401) setError(account ? '管理员账号或密码不正确。' : '管理员令牌无效。')
      else if (reason instanceof ApiError && reason.status === 429) setError('登录尝试过于频繁，请稍后重试。')
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
        {account && <><label htmlFor="admin-username">{tr('管理员账号')}</label>
          <div className="input-with-icon"><UserRound size={16} /><input id="admin-username" autoComplete="username" required autoFocus maxLength={64}
            readOnly={submitting} value={username} onChange={event => setUsername(event.target.value)} /></div></>}
        {method !== 'loading' && <>
          <label htmlFor="admin-token">{tr(account ? '管理员密码' : '管理员令牌')}</label>
          <div className="input-with-icon"><KeyRound size={16} /><input id="admin-token" type={visible ? 'text' : 'password'} required readOnly={submitting}
            aria-invalid={invalidCredential} aria-describedby={account ? 'admin-token-error' : 'admin-token-help admin-token-error'} autoComplete="current-password" autoFocus={!account}
            spellCheck={false} value={credential} maxLength={account ? 72 : undefined} onChange={event => { setCredential(event.target.value); setError('') }} />
            <button type="button" className="token-visibility-button" aria-label={tr(visible ? '隐藏输入' : '显示输入')}
              aria-pressed={visible} onClick={() => setVisible(value => !value)}>{visible ? <EyeOff size={16} /> : <Eye size={16} />}</button></div>
          {!account && <p id="admin-token-help" className="login-token-help">{tr("输入部署时配置的 ")}<code>CONTROL_ADMIN_TOKEN</code>{tr("。")}</p>}
        </>}
        <div id="admin-token-error" role="status" aria-live="polite" className={`login-error ${error ? 'visible' : ''}`}>{tr(error) || ' '}</div>
        <button className="button primary login-button" type="submit" disabled={submitting || method === 'loading'}>{submitting ? <><div className="spinner light" />{tr("验证中…")}</> : <>{tr("进入控制台")}<ArrowRight size={16} /></>}</button>
        {passwordAvailable && <button type="button" className="button" disabled={submitting} onClick={() => {
          setCredential(''); setVisible(false); setError(''); setMethod(account ? 'token' : 'password')
        }}>{tr(account ? '使用管理令牌登录' : '使用账号密码登录')}</button>}
        <div className="session-note"><CircleCheck size={14} />{tr("令牌仅保存在当前标签页会话中")}</div>
      </form>
    </section>
  </main>
}
