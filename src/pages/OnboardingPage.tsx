import { useEffect, useState } from "react";
import { getPermissionStatus, getDaemonStatus, getSettings, startDaemonElevated } from "../lib/clientApi";
import type { PermissionStatus, DaemonStatus } from "../types/client";
import { StatusPill } from "../components/StatusPill";
import { ShieldAlert, Copy, Settings, CheckCircle2, RefreshCw, ArrowRight, ShieldCheck } from "lucide-react";
import { useNavigate } from "react-router-dom";
import ControlAuthPanel from "../components/ControlAuthPanel";

export default function OnboardingPage() {
  const [permissions, setPermissions] = useState<PermissionStatus | null>(null);
  const [daemon, setDaemon] = useState<DaemonStatus | null>(null);
  const [copied, setCopied] = useState(false);
  const [checking, setChecking] = useState(false);
  const [startingElevated, setStartingElevated] = useState(false);
  const [startMessage, setStartMessage] = useState<string | null>(null);
  const [showControlAuth, setShowControlAuth] = useState(false);
  const navigate = useNavigate();

  const runChecks = async () => {
    setChecking(true);
    try {
      const [permRes, daemonRes] = await Promise.all([
        getPermissionStatus(),
        getDaemonStatus(),
      ]);
      setPermissions(permRes.data);
      setDaemon(daemonRes.data);
    } catch {
      // ignore
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    runChecks();
  }, []);

  const getSudoCommand = () => {
    return permissions?.sudoCommand ?? "sudo -E p2pnet-daemon --diagnostics-bind 127.0.0.1:39277";
  };

  const copyCommand = () => {
    navigator.clipboard.writeText(getSudoCommand());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const skipOnboarding = () => {
    localStorage.setItem("p2wlan.setup.completed", "true");
    window.dispatchEvent(new Event("storage"));
    navigate("/dashboard");
  };

  const startTunMode = async () => {
    setStartingElevated(true);
    setStartMessage(null);
    if (!getSettings().authToken.trim()) {
      setShowControlAuth(true);
      setStartMessage("请先登录或注册控制面账号，认证成功后会继续启动 TUN 模式。");
      setStartingElevated(false);
      return;
    }
    try {
      const res = await startDaemonElevated();
      if (res.error || !res.data.started) {
        throw new Error(res.data.message || res.error || "提权启动失败");
      }
      setStartMessage(res.data.message);
      setShowControlAuth(false);
      await runChecks();
    } catch (err) {
      setStartMessage(err instanceof Error ? err.message : "提权启动失败");
    } finally {
      setStartingElevated(false);
    }
  };

  // Evaluate setup states
  const isControlConfigured = daemon ? daemon.controlServer && daemon.controlServer.length > 0 : false;
  const isDaemonRunning = daemon ? daemon.lifecycle === "running" : false;
  const isPermissionsReady = permissions ? !permissions.needsElevation : false;

  return (
    <div className="page-container onboarding-container">
      <div className="page-header onboarding-header">
        <div>
          <h2>配置向导</h2>
          <p className="page-subtitle">检查守护进程连通性、控制面配置和虚拟网卡权限。</p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={skipOnboarding}>
          <span>跳过</span>
          <ArrowRight size={14} />
        </button>
      </div>

      {permissions?.needsElevation && (
        <div className="banner banner-error flex-col items-start gap-xs">
          <span className="banner-title flex-row gap-xs items-center">
            <ShieldAlert size={16} /> 需要提权
          </span>
          <span className="banner-desc">
            守护进程以普通用户运行时，无法创建 TUN 网卡或修改系统路由。
          </span>
        </div>
      )}

      <div className="panel-section">
        <div className="panel-header">
          <h3>检查清单</h3>
          <button className="btn btn-ghost btn-xs" onClick={runChecks} disabled={checking}>
            <RefreshCw size={12} className={checking ? "spin" : ""} />
            <span>重新检查</span>
          </button>
        </div>
        <div className="panel-body flex-col gap-md">
          {/* Step 1 */}
          <div className="flex-row justify-between items-center py-xs border-b border-light">
            <div className="flex-col">
              <span className="font-semibold text-sm">1. 控制面地址已配置</span>
              <span className="text-xs text-secondary">
                {daemon ? daemon.controlServer : "正在读取服务器配置..."}
              </span>
            </div>
            {isControlConfigured ? <CheckCircle2 size={16} className="text-success" /> : <StatusPill label="待配置" tone="warn" />}
          </div>

          {/* Step 2 */}
          <div className="flex-row justify-between items-center py-xs border-b border-light">
            <div className="flex-col">
              <span className="font-semibold text-sm">2. 守护进程可访问</span>
              <span className="text-xs text-secondary">检查本地诊断端点是否响应。</span>
            </div>
            {isDaemonRunning ? <CheckCircle2 size={16} className="text-success" /> : <StatusPill label="已停止" tone="bad" />}
          </div>

          {/* Step 3 */}
          <div className="flex-row justify-between items-center py-xs border-b border-light">
            <div className="flex-col">
              <span className="font-semibold text-sm">3. 本机虚拟网卡权限</span>
              <span className="text-xs text-secondary">检查 TUN 和路由修改是否需要提权。</span>
            </div>
            {isPermissionsReady ? <CheckCircle2 size={16} className="text-success" /> : <StatusPill label="需要提权" tone="bad" />}
          </div>

          {/* Step 4 */}
          <div className="flex-row justify-between items-center py-xs border-b border-light">
            <div className="flex-col">
              <span className="font-semibold text-sm">4. 隧道网卡检查</span>
              <span className="text-xs text-secondary">确认虚拟网卡和 Overlay 路由状态。</span>
            </div>
            {isDaemonRunning && isPermissionsReady ? <CheckCircle2 size={16} className="text-success" /> : <StatusPill label="未知" tone="muted" />}
          </div>
        </div>
      </div>

      {permissions?.needsElevation && (
        <div className="panel-section">
          <div className="panel-header">
            <h3>建议操作</h3>
          </div>
          <div className="panel-body flex-col gap-sm">
            <p className="text-sm text-secondary">
              点击按钮会交给系统管理员授权。macOS 可能在短时间内复用刚输入过的授权，因此重复启动不一定再次弹窗；p2wlan 不会读取或保存密码。
            </p>
            <p className="text-xs text-muted">
              备用方式：{permissions.recommendedAction}
            </p>
            <button className="btn btn-primary" onClick={startTunMode} disabled={startingElevated}>
              <ShieldCheck size={14} />
              <span>{startingElevated ? "等待系统授权..." : "授权启动 TUN 模式"}</span>
            </button>
            {startMessage && (
              <div className="banner banner-info">
                <span className="banner-desc">{startMessage}</span>
              </div>
            )}
            {showControlAuth && (
              <ControlAuthPanel
                onAuthenticated={async () => {
                  await startTunMode();
                }}
              />
            )}
            <div className="sudo-command-box flex-col gap-xs mt-sm">
              <span className="text-xs text-muted font-mono">终端命令</span>
              <div className="flex-row justify-between items-center gap-md">
                <code className="text-xs text-mono sudo-command-text">
                  {getSudoCommand()}
                </code>
                <button className="btn btn-ghost btn-sm" onClick={copyCommand}>
                  <Copy size={12} />
                  <span>{copied ? "已复制" : "复制"}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="onboarding-actions flex-row justify-between items-center gap-md">
        <button className="btn btn-ghost" onClick={() => navigate("/settings")}>
          <Settings size={14} />
          <span>配置设置</span>
        </button>
        
        {isDaemonRunning && isPermissionsReady ? (
          <button className="btn btn-primary" onClick={skipOnboarding}>
            <span>打开仪表盘</span>
            <ArrowRight size={14} />
          </button>
        ) : (
          <button className="btn btn-ghost btn-dashed" onClick={skipOnboarding}>
            <span>确认并继续</span>
          </button>
        )}
      </div>
    </div>
  );
}
