import {
  type CandidatePairDiagnostics,
  type ConnectionType,
  type PeerDiagnostics,
  type PeerPath,
  type PeerStatus,
} from "../../../types/client";

import { RELAY_PRESENTATION_FRESH_MS } from "../types";

function endpointHost(endpoint: string | null | undefined): string | null {
  const value = endpoint?.trim();
  if (!value) return null;
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    return end > 1 ? value.slice(1, end).toLowerCase() : null;
  }
  const separator = value.lastIndexOf(":");
  return (separator > 0 ? value.slice(0, separator) : value).toLowerCase();
}

function isPrivateEndpoint(endpoint: string | null | undefined): boolean {
  const host = endpointHost(endpoint);
  if (!host) return false;
  if (host === "localhost" || host === "::1") return true;
  if (host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) return true;
  const octets = host.split(".").map(part => Number(part));
  if (octets.length !== 4 || octets.some(part => !Number.isInteger(part))) return false;
  const [a, b] = octets;
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function directPairForPresentation(peer: PeerDiagnostics): CandidatePairDiagnostics | null {
  return peer.current_direct_pair ?? peer.selected_pair ?? null;
}

function directPairLatencyMs(peer: PeerDiagnostics): number | null {
  const pair = directPairForPresentation(peer);
  return pair?.rtt_ewma_ms ?? pair?.rtt_ms ?? peer.direct.latency_ms;
}

function minNullable(values: Array<number | null | undefined>): number | null {
  const present = values.filter((value): value is number => value != null);
  return present.length ? Math.min(...present) : null;
}

function pathSuccessAgeMs(peer: PeerDiagnostics, path: PeerPath): number | null {
  if (path === "relay") return peer.relay.last_success_age_ms;
  if (path === "direct") return peer.direct.last_success_age_ms;
  return minNullable([peer.direct.last_success_age_ms, peer.relay.last_success_age_ms]);
}

function hasFreshRelayConfirmation(peer: PeerDiagnostics): boolean {
  return (
    peer.relay.last_success_age_ms != null &&
    peer.relay.last_success_age_ms <= RELAY_PRESENTATION_FRESH_MS &&
    peer.relay.consecutive_failures === 0
  );
}

function controlLastSeenAgeMs(peer: PeerDiagnostics): number | null {
  if (!peer.last_seen) return null;
  const timestampMs = peer.last_seen < 10_000_000_000 ? peer.last_seen * 1000 : peer.last_seen;
  const ageMs = Date.now() - timestampMs;
  return Number.isFinite(ageMs) ? Math.max(0, ageMs) : null;
}

function connectionPresentation(
  peer: PeerDiagnostics,
  path: PeerPath
): { type: ConnectionType; label: string; detail: string } {
  const pair = directPairForPresentation(peer);
  const endpoint = pair?.remote_endpoint ?? peer.endpoint ?? null;
  const reason = peer.current_path_selection?.reason;
  const relayHedged = peer.current_path_selection?.relay_hedged === true;

  if (path === "offline") {
    if (peer.online === false) {
      return {
        type: "offline",
        label: "离线",
        detail: "控制面标记该设备离线；等待对端重新注册或续租",
      };
    }
    return {
      type: "offline",
      label: "不可达",
      detail:
        peer.warning ??
        peer.relay.last_error ??
        peer.direct.last_error ??
        "当前没有可用路径",
    };
  }

  if (path === "connecting") {
    const waitingForRelay =
      peer.state === "fallback_to_relay" || peer.current_path_selection?.path === "relay";
    return {
      type: "connecting",
      label: waitingForRelay ? "中继确认中" : "连接中",
      detail:
        reason ??
        (waitingForRelay
          ? `直连仍在探测，正在等待 relay peer 确认${peer.direct.last_error ? `：${peer.direct.last_error}` : ""}`
          : endpoint
            ? `正在验证 ${endpoint}`
            : "正在建立可用路径"),
    };
  }

  if (path === "relay") {
    const directFailure = peer.direct.last_error ? `；直连不可用：${peer.direct.last_error}` : "";
    return {
      type: "relay",
      label: peer.direct.last_error ? "中继兜底" : "中继",
      detail:
        (reason ?? (peer.relay_server ? `通过 ${peer.relay_server}` : "当前流量经中继转发")) +
        directFailure,
    };
  }

  if (path === "direct_trial") {
    return {
      type: "direct_trial",
      label: "直连试探",
      detail: reason ?? (endpoint ? `正在验证 ${endpoint}` : "正在验证直连路径"),
    };
  }

  if (path === "direct") {
    const directType = pair?.direct_type ?? peer.direct_type;
    if (pair?.is_public_udp_direct || directType === "public_udp") {
      return {
        type: "public_direct",
        label: relayHedged ? "公网直连 + 中继备用" : "公网直连",
        detail: relayHedged
          ? reason ?? (endpoint ? `当前直连端点 ${endpoint}，同时发送中继备用流量` : "当前走公网 UDP 直连，并启用中继备用")
          : endpoint
            ? `当前直连端点 ${endpoint}`
            : "当前走公网 UDP 直连",
      };
    }
    if (directType === "lan") {
      return {
        type: "lan_direct",
        label: "局域网直连",
        detail: endpoint ? `当前直连端点 ${endpoint}` : "当前走局域网直连",
      };
    }
    if (pair?.is_overlay_direct || directType === "overlay") {
      return {
        type: "overlay_direct",
        label: "Overlay 直连",
        detail: endpoint ? `当前直连端点 ${endpoint}` : "当前走 overlay 端点直连",
      };
    }
    if (endpoint && isPrivateEndpoint(endpoint)) {
      return {
        type: "lan_direct",
        label: "局域网直连",
        detail: `当前直连端点 ${endpoint}`,
      };
    }
    if (directType === "probing") {
      return {
        type: "direct_trial",
        label: "直连试探",
        detail: endpoint ? `正在验证 ${endpoint}` : "正在验证直连路径",
      };
    }
    return {
      type: "direct",
      label: relayHedged ? "直连 + 中继备用" : "直连",
      detail: relayHedged
        ? reason ?? (endpoint ? `当前直连端点 ${endpoint}，同时发送中继备用流量` : "当前走直连路径，并启用中继备用")
        : endpoint
          ? `当前直连端点 ${endpoint}`
          : "当前走直连路径",
    };
  }

  return {
    type: "unknown",
    label: "未知",
    detail: "当前路径类型未知",
  };
}

export function mapPeer(peer: PeerDiagnostics): PeerStatus {
  const selection = peer.current_path_selection;
  const isDirectTrial =
    selection?.path === "direct" &&
    selection?.reason_code === "path_direct_trial" &&
    (selection?.relay_hedged === true ||
      peer.active_path === null ||
      peer.active_path === undefined);
  const path: PeerPath = isDirectTrial
    ? "direct_trial"
    : peer.online === false
      ? "offline"
      : peer.active_path ??
        (selection?.path === "relay" && hasFreshRelayConfirmation(peer)
          ? "relay"
          : selection?.path === "relay" ||
              peer.state === "fallback_to_relay" ||
              peer.state === "hole_punching" ||
              peer.state === "connecting"
            ? "connecting"
            : "offline");
  const pathErrors = [peer.direct, peer.relay]
    .filter(health => health.last_error)
    .sort(
      (left, right) =>
        (left.last_failure_age_ms ?? Number.POSITIVE_INFINITY) -
        (right.last_failure_age_ms ?? Number.POSITIVE_INFINITY)
    );
  const lastActiveMs =
    peer.online === false
      ? controlLastSeenAgeMs(peer) ?? pathSuccessAgeMs(peer, path) ?? peer.connected_for_ms
      : pathSuccessAgeMs(peer, path) ?? peer.connected_for_ms ?? controlLastSeenAgeMs(peer);
  const latencyMs =
    path === "direct"
      ? directPairLatencyMs(peer)
      : path === "direct_trial"
        ? directPairLatencyMs(peer) ?? peer.relay.latency_ms
        : path === "relay"
          ? peer.relay.latency_ms
          : null;
  const presentation = connectionPresentation(peer, path);
  return {
    id: peer.node_id,
    name: peer.device_name?.trim() || peer.node_id.slice(0, 12),
    virtualIp: peer.virtual_ip,
    state: peer.state,
    path,
    connectionType: presentation.type,
    connectionLabel: presentation.label,
    connectionDetail: presentation.detail,
    latencyMs,
    endpoint: peer.endpoint ?? "",
    natType: peer.nat_type || "unknown",
    lastActiveMs,
    bytesSent: peer.bytes_sent,
    bytesReceived: peer.bytes_received,
    relayServer: peer.relay_server,
    lastError: pathErrors[0]?.last_error ?? null,
    candidates: peer.candidates,
    directHealth: peer.direct,
    relayHealth: peer.relay,
    selectedPair: peer.selected_pair,
    currentDirectPair: peer.current_direct_pair,
    pathSelectionReason: peer.current_path_selection?.reason ?? null,
    pathSelectionReasonCode: peer.current_path_selection?.reason_code ?? null,
  };
}
