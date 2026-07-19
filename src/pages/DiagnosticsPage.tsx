import { useEffect, useState } from "react";
import { getDiagnostics, openLogs, getPermissionStatus, getDaemonStatus } from "../lib/clientApi";
import type { DaemonStatus, DiagnosticsReport, PermissionStatus } from "../types/client";
import { StatusPill, checkTone, zhLabel } from "../components/StatusPill";
import {
  Activity,
  RefreshCw,
  FolderOpen,
  Terminal,
  AlertCircle,
  ShieldAlert,
  ShieldCheck,
  Copy,
} from "lucide-react";

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

  const handleCopySummary = async () => {
    if (!report || !daemon) {
      setLogStatus("诊断数据尚未准备好，请稍后重试。");
      return;
    }
    const summary = `
================ p2wlan 诊断报告 ================
生成时间: ${new Date(report.generatedAt).toLocaleString()}
运行平台: ${permissions?.platform ?? "unknown"}
数据来源: ${zhLabel(report.source)}
守护进程状态: ${daemon.lifecycle} (可达: ${daemon.reachable ? "是" : "否"})
本机节点 ID: ${daemon.nodeId || "未分配"}
虚拟内网 IP: ${daemon.virtualIp || "未分配"}
控制面地址: ${daemon.controlServer}
在线节点总数: ${daemon.peerStats.total_peers}
直连连接数: ${daemon.peerStats.direct_connections}
中继连接数: ${daemon.peerStats.relay_connections}
节点链路摘要: ${daemon.activePathSummary}
最近一次错误: ${daemon.lastError || "无"}

检查详情:
${report.checks.map(c => ` - [${c.status.toUpperCase()}] ${c.name}: ${c.detail}`).join("\n")}

最近日志:
${report.logs.slice(-80).join("\n") || "无"}
================================================
    `.trim();

    try {
      await navigator.clipboard.writeText(summary);
      setLogStatus("诊断摘要已成功复制到剪贴板。");
      setTimeout(() => setLogStatus(null), 3000);
    } catch {
      setLogStatus("复制诊断摘要失败。");
    }
  };

  if (loading) {
    return (
      <div className="page-container flex items-center justify-center py-xl">
        <Activity size={24} className="spin text-muted mb-sm" />
        <span className="text-secondary">正在收集系统及网络诊断信息...</span>
      </div>
    );
  }

  const checkCounts = report
    ? {
        pass: report.checks.filter((c) => c.status === "pass").length,
        warn: report.checks.filter((c) => c.status === "warn").length,
        fail: report.checks.filter((c) => c.status === "fail").length,
      }
    : { pass: 0, warn: 0, fail: 0 };
  const daemonRunning = daemon?.lifecycle === "running" && daemon.reachable;
  const permissionReady = daemonRunning || (permissions ? !permissions.needsElevation : false);

  return (
    <div className="page-container diagnostics-page">
      <div className="page-header">
        <div>
          <h2>诊断</h2>
          <p className="page-subtitle">深入排查本地守护进程生命周期、系统网卡与物理连接细节。</p>
        </div>
        <div className="header-actions">
          <button className="btn btn-ghost btn-sm" onClick={handleCopySummary} disabled={!report}>
            <Copy size={14} />
            <span>复制摘要</span>
          </button>
          <button className="btn btn-ghost btn-sm" onClick={handleOpenLogsDir}>
            <FolderOpen size={14} />
            <span>日志目录</span>
          </button>
          <button
            className="btn btn-primary btn-sm"
            onClick={() => fetchDiagnostics(true)}
            disabled={refreshing}
          >
            <RefreshCw size={14} className={refreshing ? "spin" : ""} />
            <span>重新检查</span>
          </button>
        </div>
      </div>

      {/* Summary Strip */}
      <div className="summary-strip">
        <div className="summary-item">
          <span className="summary-label">检查通过</span>
          <span className="summary-value text-success">{checkCounts.pass}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">警告项</span>
          <span className="summary-value text-warning">{checkCounts.warn}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">阻碍失败</span>
          <span className="summary-value text-danger">{checkCounts.fail}</span>
        </div>
        <div className="summary-item">
          <span className="summary-label">快照类型</span>
          <span className="summary-value">{zhLabel(report?.source || "fallback")}</span>
        </div>
      </div>

      {permissions && (
        <div className={`banner banner-${permissionReady ? "info" : "error"}`}>
          {permissionReady ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
          <div className="banner-content">
            <span className="banner-title">
              平台特权状态 ({permissions.platform})：{permissionReady ? "已获取" : "需要系统授权"}
            </span>
            <span className="banner-desc">
              {daemonRunning
                ? "守护进程正常通过管理员特权运行，可用 Overlay 虚拟网卡及本地路由表操作。"
                : permissions.recommendedAction}
            </span>
          </div>
        </div>
      )}

      {error && (
        <div className="banner banner-error">
          <AlertCircle size={16} />
          <div className="banner-content">
            <span className="banner-title">诊断异常信息</span>
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
        {/* Left Column: Diagnostics Check Items */}
        <div className="column flex-col gap-md">
          <div className="panel-section">
            <div className="panel-header">
              <h3>状态检查矩阵</h3>
            </div>

            <div className="panel-body flex-col gap-sm">
              {report?.checks.map((check) => (
                <div
                  key={check.id}
                  className="diagnostics-check-item flex-row justify-between items-center py-xs border-b border-light"
                >
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
              <h3>控制台事件日志</h3>
              <span className="text-xs text-secondary">展示近期 {report?.logs.length || 0} 条日志缓冲</span>
            </div>
            <div className="panel-body flex-1 flex-col p-none">
              <div className="console-log-buffer">
                {report?.logs && report.logs.length > 0 ? (
                  <pre className="logs-pre">
                    {report.logs.map((log, idx) => (
                      <code key={idx} className="log-line">
                        {log}
                      </code>
                    ))}
                  </pre>
                ) : (
                  <div className="empty-state-text py-xl text-center">暂无诊断日志事件。</div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
