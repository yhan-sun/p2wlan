import { type DiagnosticsSnapshot } from "../../../types/client";

export function udpPoolSummary(snapshot: DiagnosticsSnapshot | null): string | null {
  const socketCount = snapshot?.udp_socket_count ?? 0;
  if (socketCount <= 1) return null;
  const members = snapshot?.udp_socket_pool ?? [];
  const probes = members.reduce((sum, member) => sum + (member.probes_sent ?? 0), 0);
  const acksReceived = members.reduce((sum, member) => sum + (member.probe_acks_received ?? 0), 0);
  const acksSent = members.reduce((sum, member) => sum + (member.probe_acks_sent ?? 0), 0);
  const stunMappings = members.reduce(
    (sum, member) => sum + (member.stun_mappings_discovered ?? 0),
    0
  );
  return `socket pool=${socketCount} ${snapshot?.udp_socket_pool_active ? "active" : "standby"}, STUN映射=${stunMappings}, probe=${probes}, ACK=${acksReceived}/${acksSent}`;
}

export function natProfileSummary(snapshot: DiagnosticsSnapshot | null): string | null {
  const profile = snapshot?.nat_profile;
  if (!profile) return null;
  const parts = [
    profile.mapping_behavior ? `mapping=${profile.mapping_behavior}` : null,
    profile.filtering_behavior ? `filter=${profile.filtering_behavior}` : null,
    profile.public_endpoint ? `public=${profile.public_endpoint}` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(" ") : null;
}
