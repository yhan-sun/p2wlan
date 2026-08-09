// Diagnostics report assembly for the unified client API.
//
// Split out of `clientApi.ts`.

import type {
  ApiResult,
  CandidatePairSourceStats,
  ClientSettings,
  DiagnosticCheck,
  DiagnosticsReport,
  DiagnosticsSnapshot,
} from "../../types/client";

import { appendLog, getRecentLogs } from "./log";
import { getSettings } from "./config";
import { fetchDiagnosticsSnapshot } from "./http";
import {
  getDaemonStatus,
  getRouteStatus,
  natProfileSummary,
  udpPoolSummary,
} from "./status";
import { MAX_LOG_LINES } from "./types";

function formatPerMille(value: number | null | undefined): string {
  if (value == null) return "n/a";
  return `${(value / 10).toFixed(1)}%`;
}

function formatCooldown(ms: number | null | undefined): string | null {
  if (ms == null || ms <= 0) return null;
  return `cooldown=${Math.ceil(ms / 1000)}s`;
}

function interestingCandidateSourceStats(snapshot: DiagnosticsSnapshot | null): Array<{
  peerId: string;
  stats: CandidatePairSourceStats;
}> {
  if (!snapshot) return [];
  return snapshot.peers.flatMap((peer) =>
    (peer.candidate_pair_stats ?? [])
      .filter(
        (stats) =>
          stats.source === "predicted" ||
          stats.source === "birthday" ||
          (stats.history_cooldown_remaining_ms ?? 0) > 0
      )
      .map((stats) => ({ peerId: peer.node_id, stats }))
  );
}

function candidateSourcePolicyCheck(
  snapshot: DiagnosticsSnapshot | null
): Pick<DiagnosticCheck, "status" | "detail"> | null {
  const rows = interestingCandidateSourceStats(snapshot);
  if (rows.length === 0) return null;

  const hasCooldown = rows.some(({ stats }) => (stats.history_cooldown_remaining_ms ?? 0) > 0);
  const hasZeroBudget = rows.some(({ stats }) => stats.probe_budget_per_cycle === 0);
  const detail = rows
    .slice(0, 6)
    .map(({ peerId, stats }) => {
      const budget =
        stats.probe_budget_per_cycle == null
          ? "budget=guaranteed"
          : `budget=${stats.probe_budget_per_cycle}`;
      const cooldown = formatCooldown(stats.history_cooldown_remaining_ms);
      return [
        `${peerId.slice(0, 8)} ${stats.source}`,
        `pairs=${stats.current_pair_count}/${stats.pair_count}`,
        `rate=${formatPerMille(stats.success_rate_per_mille)}`,
        `history=${formatPerMille(stats.history_success_rate_per_mille)}`,
        budget,
        `reason=${stats.probe_budget_reason ?? "unknown"}`,
        cooldown,
      ]
        .filter(Boolean)
        .join(" ");
    })
    .join("; ");

  return {
    status: hasCooldown || hasZeroBudget ? "warn" : "pass",
    detail,
  };
}

function yesNo(value: boolean): string {
  return value ? "yes" : "no";
}

function protocolBoundaryDetail(protocol: NonNullable<DiagnosticsSnapshot["protocol"]>): string {
  return [
    protocol.data_plane,
    `handshake=${protocol.handshake}`,
    `aead=${protocol.aead}`,
    `wg-interop=${yesNo(protocol.wireguard_interop)}`,
    `turn=${yesNo(protocol.turn_compatible)}`,
    `audit=${protocol.security_audit}`,
  ].join(" ");
}

function protocolBoundaryStatus(
  protocol: NonNullable<DiagnosticsSnapshot["protocol"]>
): DiagnosticCheck["status"] {
  return protocol.security_audit === "completed" ? "pass" : "warn";
}

function mtuRuntimeDetail(
  mtu: NonNullable<DiagnosticsSnapshot["mtu"]>,
  settings: ClientSettings,
  relayConnections: number
): string {
  const parts = [
    `runtime=${mtu.configured_mtu}`,
    `profile=${mtu.profile}`,
    `relay-safe=${mtu.relay_safe_mtu}`,
    `auto-pmtu=${yesNo(mtu.automatic_pmtu)}`,
  ];
  if (mtu.configured_mtu !== settings.mtu) {
    parts.push(`config=${settings.mtu} pending-restart`);
  }
  if (relayConnections > 0 && mtu.configured_mtu > mtu.relay_safe_mtu) {
    parts.push(`relay-risk=${relayConnections}`);
  }
  return parts.join(" ");
}

function mtuRuntimeStatus(
  mtu: NonNullable<DiagnosticsSnapshot["mtu"]>,
  settings: ClientSettings,
  relayConnections: number
): DiagnosticCheck["status"] {
  if (mtu.configured_mtu !== settings.mtu) return "warn";
  if (relayConnections > 0 && mtu.configured_mtu > mtu.relay_safe_mtu) return "warn";
  if (!mtu.automatic_pmtu && mtu.configured_mtu > mtu.wireguard_style_mtu) return "warn";
  return "pass";
}

export async function getDiagnostics(): Promise<ApiResult<DiagnosticsReport>> {
  const settings = getSettings();
  const statusResult = await getDaemonStatus();
  const status = statusResult.data;
  const snapshot =
    statusResult.source === "live"
      ? await fetchDiagnosticsSnapshot(status.diagnosticsUrl)
      : null;

  const checks: DiagnosticCheck[] = [];

  checks.push({
    id: "daemon",
    name: "守护进程",
    category: "daemon",
    status: status.reachable ? "pass" : "fail",
    detail: status.reachable
      ? `可访问 (${status.healthStatus})`
      : status.lastError ?? "不可访问",
  });

  if (snapshot?.protocol) {
    checks.push({
      id: "protocol-boundary",
      name: "协议边界",
      category: "protocol",
      status: protocolBoundaryStatus(snapshot.protocol),
      detail: protocolBoundaryDetail(snapshot.protocol),
    });
  }

  checks.push({
    id: "control",
    name: "控制面",
    category: "control",
    status: !status.reachable
      ? "skipped"
      : status.reauthRequired
        ? "fail"
        : status.controlConnected
          ? "pass"
          : "warn",
    detail: !status.reachable
      ? "守护进程离线"
      : status.reauthRequired
        ? "需要重新登录"
        : status.controlConnected
          ? `connected${
              status.lastControlSuccessSecsAgo != null
                ? ` (上次成功 ${status.lastControlSuccessSecsAgo}s 前)`
                : ""
            }`
          : "未连接",
  });

  const udpDetails = !status.reachable
    ? ["守护进程离线"]
    : status.udpLocalAddr
      ? [
          `已绑定 ${status.udpLocalAddr}`,
          `直连节点=${status.peerStats.direct_connections}`,
          snapshot?.local_candidates?.length != null ? `候选=${snapshot.local_candidates.length}` : null,
          natProfileSummary(snapshot),
          udpPoolSummary(snapshot),
        ].filter(Boolean)
      : ["未获取 UDP 本地地址"];

  checks.push({
    id: "udp",
    name: "UDP / 打洞",
    category: "nat",
    status: !status.reachable
      ? "skipped"
      : status.udpLocalAddr
        ? status.peerStats.direct_connections > 0
          ? "pass"
          : "warn"
        : "fail",
    detail: udpDetails.join("; "),
  });

  const sourcePolicy = candidateSourcePolicyCheck(snapshot);
  if (sourcePolicy) {
    checks.push({
      id: "candidate-source-policy",
      name: "候选源策略",
      category: "nat",
      status: !status.reachable ? "skipped" : sourcePolicy.status,
      detail: !status.reachable ? "守护进程离线" : sourcePolicy.detail,
    });
  }

  const gatewayMapping = snapshot?.gateway_mapping;
  if (gatewayMapping) {
    const methods = [
      ["UPnP", gatewayMapping.upnp],
      ["PCP", gatewayMapping.pcp],
      ["NAT-PMP", gatewayMapping.nat_pmp],
    ] as const;
    const failed = methods.find(([, method]) => method.status === "failed");
    checks.push({
      id: "gateway-mapping",
      name: "网关端口映射",
      category: "nat",
      status: !status.reachable
        ? "skipped"
        : !gatewayMapping.enabled
          ? "skipped"
          : gatewayMapping.candidate_endpoint
            ? "pass"
            : "warn",
      detail: !status.reachable
        ? "守护进程离线"
        : !gatewayMapping.enabled
          ? "已在配置中关闭"
          : gatewayMapping.candidate_endpoint
            ? `${gatewayMapping.candidate_source ?? "gateway"} 映射 ${gatewayMapping.candidate_endpoint}（租约 ${gatewayMapping.lease_seconds}s）`
            : failed
              ? `${failed[0]}：${failed[1].last_error ?? "映射失败"}`
              : "尚未发现支持 UPnP / PCP / NAT-PMP 的网关",
    });
  }

  checks.push({
    id: "relay",
    name: "中继连通性",
    category: "relay",
    status: !status.reachable
      ? "skipped"
      : status.relayConnected
        ? "pass"
        : status.relayServers.length > 0
          ? "warn"
          : "unknown",
    detail: !status.reachable
      ? "守护进程离线"
      : status.relayConnected
        ? `已连接 ${status.relayRegion ?? ""} ${status.relayEndpoint ?? ""}`.trim()
        : status.relayServers.length > 0
          ? `已配置但未连接 (${status.relayServers.length} 个候选)`
          : "未配置中继服务器",
    latencyMs: snapshot?.relay_selection.selected_connect_latency_ms ?? null,
  });

  checks.push({
    id: "tun",
    name: "TUN 网卡",
    category: "tun",
    status: !status.reachable
      ? "skipped"
      : status.virtualIp
        ? "pass"
        : "warn",
    detail: !status.reachable
      ? "守护进程离线"
      : status.virtualIp
        ? `${settings.tunInterface} ${status.virtualIp} mtu=${settings.mtu}`
        : "尚未分配虚拟 IP",
  });

  if (snapshot?.mtu) {
    checks.push({
      id: "mtu-policy",
      name: "MTU 策略",
      category: "performance",
      status: mtuRuntimeStatus(snapshot.mtu, settings, status.peerStats.relay_connections),
      detail: mtuRuntimeDetail(snapshot.mtu, settings, status.peerStats.relay_connections),
    });
  }

  const route = await getRouteStatus();
  const routeState = route.data.entries[0]?.state ?? "unknown";
  checks.push({
    id: "route",
    name: "Overlay 路由",
    category: "route",
    status:
      routeState === "installed"
        ? "pass"
        : routeState === "missing"
          ? "fail"
          : routeState === "conflict"
            ? "fail"
            : "unknown",
    detail: route.data.entries[0]?.detail ?? "unknown",
  });

  if (snapshot) {
    for (const peer of snapshot.peers.slice(0, 8)) {
      if (peer.direct.last_error || peer.relay.last_error) {
        checks.push({
          id: `peer-${peer.node_id}`,
          name: `节点 ${peer.node_id.slice(0, 8)}`,
          category: "nat",
          status: peer.active_path ? "warn" : "fail",
          detail: peer.direct.last_error ?? peer.relay.last_error ?? peer.state,
        });
      }
    }
  }

  const logs = getRecentLogs(300);
  if (statusResult.error) {
    appendLog(`diagnostics: ${statusResult.error}`);
  }
  const appLogs = getRecentLogs(300).length ? getRecentLogs(300) : logs;
  const combinedLogs = appLogs.slice(-MAX_LOG_LINES);

  return {
    data: {
      checks,
      logs: combinedLogs,
      protocol: snapshot?.protocol,
      mtu: snapshot?.mtu,
      source: statusResult.source,
      generatedAt: Date.now(),
    },
    source: statusResult.source,
    error: statusResult.error,
  };
}
