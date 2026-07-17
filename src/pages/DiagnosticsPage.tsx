import { useEffect, useState } from "react";
import { getDiagnostics, openLogs, getPermissionStatus, getDaemonStatus } from "../lib/clientApi";
import type { DaemonStatus, DiagnosticsReport, PermissionStatus } from "../types/client";
import { StatusPill, checkTone, zhLabel } from "../components/StatusPill";
import { Activity, RefreshCw, FolderOpen, Terminal, AlertCircle, ShieldAlert, ShieldCheck } from "lucide-react";

export default function DiagnosticsPage() {
  const [report, setReport] = useState<DiagnosticsReport | null>(null);
  const [permissions, setPermissions] = useState<PermissionStatus | null>(null);
  const [daemon, setDaemon] = useState<DaemonStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logStatus, setLogStatus] = useState<string | null>(null);

  const fetchDiagnostics = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const [diagRes, permRes, daemonRes] = await Promise.all([
        getDiagnostics(),
        getPermissionStatus(),
        getDaemonStatus(),
      ]);
      setReport(diagRes.data);
      setPermissions(permRes.data);
      setDaemon(daemonRes.data);
      if (diagRes.error && diagRes.source === "fallback") {
        setError(diagRes.error);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "无法读取诊断信息。");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDiagnostics();
  }, []);

  const handleOpenLogsDir = async () => {
    setLogStatus(null);
    try {
      const res = await openLogs();
      setLogStatus(res.data.message);
      setTimeout(() => setLogStatus(null), 3000);
    } catch (e) {
      setLogStatus(e instanceof Error ? e.message : "无法打开日志目录。");
    }
  };

  if (loading) {
    return (
      <div className="page-container flex items-center justify-center py-xl">
        <Activity size={24} className="spin text-muted mb-sm" />
        <span className="text-secondary">正在运行系统诊断...</span>
      </div>
    );
  }

  const checkCounts = report ? {
    pass: report.checks.filter(c => c.status === "pass").length,
    warn: report.checks.filter(c => c.status === "warn").length,
    fail: report.checks.filter(c => c.status === "fail").length,
  } : { pass: 0, warn: 0, fail: 0 };
  const daemonRunning = daemon?.lifecycle === "running" && daemon.reachable;
  const permissionReady = daemonRunning || (permissions ? !permissions.needsElevation : false);

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h2>诊断</h2>
          <p className="page-subtitle">检查本地守护进程、控制面、中继、TUN 和路由状态。</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-ghost btn-sm" onClick={handleOpenLogsDir}>
            <FolderOpen size={14} />
            <span>日志</span>
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => fetchDiagnostics(true)} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? "spin" : ""} />
            <span>重新检查</span>
          </button>
        </div>
      </div>

      <div className="summary-strip">
        <div className="summary-item">
          <span className="summary-label">通过</span>
          <span className="summary-value text-success">{checkCounts.pass}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">警告</span>
          <span className="summary-value text-warning">{checkCounts.warn}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">失败</span>
          <span className="summary-value text-danger">{checkCounts.fail}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">来源</span>
          <span className="summary-value">{zhLabel(report?.source || "fallback")}</span>
        </div>
      </div>

      {permissions && (
        <div className={`banner banner-${permissionReady ? "info" : "error"}`}>
          {permissionReady ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
          <div className="banner-content">
            <span className="banner-title">
              平台权限 ({permissions.platform})：{permissionReady ? "就绪" : "需要提权"}
            </span>
            <span className="banner-desc">
              {daemonRunning
                ? "TUN daemon 已通过管理员权限运行，虚拟网卡和路由权限可用。"
                : permissions.recommendedAction}
            </span>
          </div>
        </div>
      )}

      {error && (
        <div className="banner banner-error">
          <AlertCircle size={16} />
          <div className="banner-content">
            <span className="banner-title">诊断异常</span>
            <span className="banner-desc">{error}</span>
          </div>
        </div>
      )}

      {logStatus && (
        <div className="banner banner-info">
          <Terminal size={16} />
          <div className="banner-content">
            <span className="banner-desc">{logStatus}</span>
          </div>
        </div>
      )}

      <div className="split-layout">
        {/* Left Column: Diagnostics Check Results */}
        <div className="column flex-col gap-md">
          <div className="panel-section">
            <div className="panel-header">
              <h3>检查项</h3>
              <span className="text-xs text-secondary flex-row gap-xs">
                <span className="text-success font-bold">{checkCounts.pass} 通过</span>
                <span>/</span>
                <span className="text-warning font-bold">{checkCounts.warn} 警告</span>
                <span>/</span>
                <span className="text-danger font-bold">{checkCounts.fail} 失败</span>
              </span>
            </div>
            
            <div className="panel-body flex-col gap-sm">
              {report?.checks.map((check) => (
                <div key={check.id} className="diagnostics-check-item flex-row justify-between items-center py-xs border-b border-light">
                  <div className="check-info flex-col">
                    <span className="check-title font-semibold text-sm">{check.name}</span>
                    <span className="check-details text-xs text-secondary">{check.detail}</span>
                  </div>
                  <div className="check-badge flex-row gap-xs items-center">
                    {check.latencyMs != null && (
                      <span className="text-xs text-mono text-secondary">{check.latencyMs}ms</span>
                    )}
                    <StatusPill label={zhLabel(check.status)} tone={checkTone(check.status)} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Console Log Buffer */}
        <div className="column flex-col gap-md">
          <div className="panel-section flex-1 flex-col">
            <div className="panel-header">
              <h3>日志</h3>
              <span className="text-xs text-secondary">最近 {report?.logs.length || 0} 条事件</span>
            </div>
            <div className="panel-body flex-1 flex-col p-none">
              <div className="console-log-buffer">
                {report?.logs && report.logs.length > 0 ? (
                  <pre className="logs-pre">
                    {report.logs.map((log, idx) => (
                      <code key={idx} className="log-line">{log}</code>
                    ))}
                  </pre>
                ) : (
                  <div className="empty-state-text py-xl text-center">暂无可用日志。</div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
