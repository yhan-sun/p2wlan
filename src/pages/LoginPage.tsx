import { Monitor } from "lucide-react";
import ControlAuthPanel from "../components/ControlAuthPanel";

interface LoginPageProps {
  onLogin: (token: string) => void;
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  return (
    <div className="login-page">
      <div className="login-shell">
        <section className="login-identity" aria-label="p2wlan">
          <div className="login-mark">
            <Monitor size={22} />
          </div>
          <div>
            <h1 className="login-title">p2wlan</h1>
            <p className="login-subtitle">登录控制面后启动本机 TUN</p>
          </div>
        </section>

        <ControlAuthPanel onAuthenticated={onLogin} compact />
      </div>
    </div>
  );
}
