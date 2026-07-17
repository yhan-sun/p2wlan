import { FormEvent, useState } from "react";
import { KeyRound, Mail, Server } from "lucide-react";
import { authenticateWithControl, getSettings } from "../lib/clientApi";

interface ControlAuthPanelProps {
  onAuthenticated?: (token: string) => void | Promise<void>;
  compact?: boolean;
}

export default function ControlAuthPanel({ onAuthenticated, compact = false }: ControlAuthPanelProps) {
  const [controlServer, setControlServer] = useState(() => getSettings().controlServer);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isRegister, setIsRegister] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      const res = await authenticateWithControl(
        isRegister ? "register" : "login",
        controlServer,
        email,
        password
      );
      setMessage("控制面账号已认证，token 已保存。");
      await onAuthenticated?.(res.data.token);
    } catch (err) {
      setError(err instanceof Error ? err.message : "认证失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className={`control-auth-panel ${compact ? "compact" : ""}`} onSubmit={submit}>
      <div className="form-group">
        <label className="form-label">控制服务器</label>
        <div className="input-with-icon">
          <Server size={14} />
          <input
            className="form-input"
            type="url"
            value={controlServer}
            onChange={(event) => setControlServer(event.target.value)}
            placeholder="http://47.109.40.237:18080"
            required
          />
        </div>
      </div>
      <div className="form-group-row">
        <div className="form-group">
          <label className="form-label">邮箱</label>
          <div className="input-with-icon">
            <Mail size={14} />
            <input
              className="form-input"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="user@example.com"
            autoComplete="email"
            required
          />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">密码</label>
          <div className="input-with-icon">
            <KeyRound size={14} />
            <input
              className="form-input"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="至少 6 个字符"
              autoComplete={isRegister ? "new-password" : "current-password"}
              required
            />
          </div>
        </div>
      </div>
      {error && <div className="login-error">{error}</div>}
      {message && <div className="banner banner-info"><span className="banner-desc">{message}</span></div>}
      <div className="control-auth-actions">
        <button className="btn btn-primary" type="submit" disabled={submitting}>
          <span>{submitting ? "认证中..." : isRegister ? "注册并继续" : "登录并继续"}</span>
        </button>
        <button className="login-link-button" type="button" onClick={() => setIsRegister((value) => !value)}>
          {isRegister ? "已有账号，去登录" : "没有账号，创建一个"}
        </button>
      </div>
    </form>
  );
}
