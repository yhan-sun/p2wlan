// Application log buffer helpers for the unified client API.
//
// Split out of `clientApi.ts`.

import { isTauri } from "./http";
import { tryInvoke } from "./http";
import { LOG_KEY, MAX_LOG_LINES } from "./types";

export function appendLog(line: string): void {
  const stamp = new Date().toISOString().replace("T", " ").replace("Z", "");
  const entry = `${stamp}  ${line}`;
  try {
    const existing = localStorage.getItem(LOG_KEY);
    const lines = existing ? existing.split("\n") : [];
    lines.push(entry);
    while (lines.length > MAX_LOG_LINES) lines.shift();
    localStorage.setItem(LOG_KEY, lines.join("\n"));
  } catch {
    // ignore quota errors
  }
}

export function getRecentLogs(limit = 300): string[] {
  try {
    const existing = localStorage.getItem(LOG_KEY);
    if (!existing) return [];
    const lines = existing.split("\n").filter(Boolean);
    return lines.slice(-Math.min(limit, MAX_LOG_LINES));
  } catch {
    return [];
  }
}

export async function getDaemonLogTail(limit = 120): Promise<string[]> {
  if (!isTauri()) return [];
  try {
    return (await tryInvoke<string[]>("daemon_log_tail", { maxLines: limit })) ?? [];
  } catch (err) {
    appendLog(`daemon log tail unavailable: ${err}`);
    return [];
  }
}
