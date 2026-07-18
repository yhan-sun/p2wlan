import type { ConnectionState, DiagnosticCheckStatus, HealthStatus, NetworkPath } from "../types/client";

type Tone = "ok" | "warn" | "bad" | "muted" | "info";

interface StatusPillProps {
  label: string;
  tone?: Tone;
  title?: string;
}

const toneClass: Record<Tone, string> = {
  ok: "pill pill-ok",
  warn: "pill pill-warn",
  bad: "pill pill-bad",
  muted: "pill pill-muted",
  info: "pill pill-info",
};

export function StatusPill({ label, tone = "muted", title }: StatusPillProps) {
  return (
    <span className={toneClass[tone]} title={title}>
      {label}
    </span>
  );
}

export function zhLabel(value: string | null | undefined): string {
  switch (value) {
    case "running":
      return "运行中";
    case "stopped":
      return "未启动";
    case "unknown":
      return "未知";
    case "error":
      return "异常";
    case "unreachable":
      return "不可达";
    case "connected":
      return "已连接";
    case "healthy":
      return "健康";
    case "degraded":
      return "降级";
    case "unhealthy":
      return "异常";
    case "shutting_down":
      return "关闭中";
    case "idle":
      return "空闲";
    case "connecting":
      return "连接中";
    case "hole_punching":
      return "正在打洞";
    case "direct":
      return "直连";
    case "fallback_to_relay":
      return "切换到中继";
    case "relay":
      return "中继";
    case "failed":
      return "失败";
    case "closed":
      return "已关闭";
    case "offline":
      return "离线";
    case "installed":
      return "已安装";
    case "missing":
      return "缺失";
    case "conflict":
      return "冲突";
    case "pass":
      return "通过";
    case "warn":
      return "警告";
    case "fail":
      return "失败";
    case "skipped":
      return "跳过";
    case "live":
      return "实时";
    case "fallback":
      return "推断";
    case "cached":
      return "缓存";
    default:
      return value || "—";
  }
}

export function healthTone(status: HealthStatus): Tone {
  switch (status) {
    case "healthy":
      return "ok";
    case "degraded":
      return "warn";
    case "unhealthy":
    case "shutting_down":
      return "bad";
    default:
      return "muted";
  }
}

export function pathTone(path: NetworkPath | "offline" | string): Tone {
  if (path === "direct") return "ok";
  if (path === "relay") return "warn";
  if (path === "offline") return "muted";
  return "info";
}

export function connectionTone(state: ConnectionState): Tone {
  switch (state) {
    case "direct":
      return "ok";
    case "relay":
    case "fallback_to_relay":
    case "hole_punching":
    case "connecting":
      return "warn";
    case "failed":
    case "closed":
      return "bad";
    default:
      return "muted";
  }
}

export function checkTone(status: DiagnosticCheckStatus): Tone {
  switch (status) {
    case "pass":
      return "ok";
    case "warn":
      return "warn";
    case "fail":
      return "bad";
    case "skipped":
    case "unknown":
    default:
      return "muted";
  }
}

export function formatAge(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  return `${Math.floor(min / 60)}h`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function zhPathSummary(summary: string): string {
  if (summary === "no peers") return "暂无节点";
  if (summary === "peers offline") return "节点离线";
  if (summary === "offline") return "离线";
  const direct = summary.match(/^direct \((\d+)\)$/);
  if (direct) return `直连 (${direct[1]})`;
  const relay = summary.match(/^relay \((\d+)\)$/);
  if (relay) return `中继 (${relay[1]})`;
  const mixed = summary.match(/^mixed d(\d+)\/r(\d+)$/);
  if (mixed) return `混合 直连${mixed[1]}/中继${mixed[2]}`;
  return summary;
}
