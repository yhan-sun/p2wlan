// Low-level HTTP / Tauri bridge helpers for the unified client API.
//
// Base layer for the other clientApi submodules: detects the Tauri runtime,
// invokes Tauri commands, parses JSON responses, and fetches the diagnostics
// snapshot from the daemon. Split out of `clientApi.ts`.

import type { DiagnosticsSnapshot } from "../../types/client";

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function tryInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T | null> {
  if (!isTauri()) return null;
  const { invoke } = await import("@tauri-apps/api/core");
  return (await invoke<T>(command, args)) as T;
}

export async function readJsonBody<T>(res: Response): Promise<T | null> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export function normalizeControlServer(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, "");
  const parsed = new URL(trimmed);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("控制服务器必须使用 http 或 https");
  }
  return parsed.toString().replace(/\/+$/, "");
}

export async function fetchDiagnosticsSnapshot(url: string): Promise<DiagnosticsSnapshot | null> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 3500);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as DiagnosticsSnapshot;
  } catch {
    return null;
  } finally {
    window.clearTimeout(timer);
  }
}

export async function invokeDaemonStatusSnapshot(url: string): Promise<DiagnosticsSnapshot | null> {
  if (!isTauri()) return null;
  try {
    return await tryInvoke<DiagnosticsSnapshot>("daemon_status", { diagnosticsUrl: url });
  } catch {
    return null;
  }
}
