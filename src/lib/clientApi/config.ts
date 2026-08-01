// Settings read/write and validation for the unified client API.
//
// Split out of `clientApi.ts`.

import {
  type ApiResult,
  type ClientSettings,
  type CloseBehavior,
  DEFAULT_SETTINGS,
} from "../../types/client";

import { appendLog } from "./log";
import { SETTINGS_KEY } from "./types";

export function daemonStartOptions(settings: ClientSettings) {
  return {
    diagnosticsUrl: settings.diagnosticsUrl,
    controlServer: settings.controlServer,
    authToken: settings.authToken,
    networkId: settings.networkId,
    deviceName: settings.deviceName,
    tunInterface: settings.tunInterface,
    udpBind: settings.udpBind,
    udpAdvertise: settings.udpAdvertise,
    socketPool: settings.socketPool,
    mtu: settings.mtu,
  };
}

function normalizeCloseBehavior(settings: Partial<ClientSettings>): CloseBehavior {
  if (settings.closeBehavior === "keep-running" || settings.closeBehavior === "stop-and-quit") {
    return settings.closeBehavior;
  }
  if (settings.minimizeToTray === false) return "stop-and-quit";
  return DEFAULT_SETTINGS.closeBehavior;
}

export function getSettings(): ClientSettings {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<ClientSettings>;
    const settings = { ...DEFAULT_SETTINGS, ...parsed };
    settings.closeBehavior = normalizeCloseBehavior(parsed);
    settings.minimizeToTray = settings.closeBehavior === "keep-running";
    const legacyLocalControl =
      settings.controlServer === "http://127.0.0.1:8080" ||
      settings.controlServer === "http://localhost:8080";
    if (legacyLocalControl && !settings.authToken) {
      settings.controlServer = DEFAULT_SETTINGS.controlServer;
    }
    const isWindows = typeof navigator !== "undefined" && navigator.userAgent.toLowerCase().includes("win");
    if (isWindows && settings.tunInterface === "p2pnet0") {
      settings.tunInterface = DEFAULT_SETTINGS.tunInterface;
    }
    return settings;
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(settings: ClientSettings): ApiResult<ClientSettings> {
  const errors = validateSettings(settings);
  if (errors.length > 0) {
    return { data: settings, source: "fallback", error: errors.join("; ") };
  }
  const normalizedSettings: ClientSettings = {
    ...settings,
    closeBehavior: normalizeCloseBehavior(settings),
    minimizeToTray: normalizeCloseBehavior(settings) === "keep-running",
    udpBind: settings.udpBind.trim(),
    udpAdvertise: settings.udpAdvertise.trim(),
    socketPool: normalizeSocketPool(settings.socketPool),
  };
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(normalizedSettings));
  appendLog(`settings saved (control=${settings.controlServer}, mtu=${settings.mtu})`);
  return { data: normalizedSettings, source: "live" };
}

export function validateSettings(settings: ClientSettings): string[] {
  const errors: string[] = [];
  if (!settings.controlServer.trim()) {
    errors.push("控制服务器不能为空");
  } else {
    try {
      // eslint-disable-next-line no-new
      new URL(settings.controlServer);
    } catch {
      errors.push("控制服务器必须是有效 URL");
    }
  }
  if (!settings.deviceName.trim()) {
    errors.push("设备名称不能为空");
  }
  if (settings.mtu < 576 || settings.mtu > 9000) {
    errors.push("MTU 必须在 576 到 9000 之间");
  }
  if (!settings.networkId.trim()) {
    errors.push("网络 ID 不能为空");
  }
  if (!settings.udpBind.trim()) {
    errors.push("UDP 监听地址不能为空");
  } else if (!isSocketAddress(settings.udpBind, true)) {
    errors.push("UDP 监听地址格式应类似 0.0.0.0:60207");
  }
  if (settings.udpAdvertise.trim()) {
    if (!isSocketAddress(settings.udpAdvertise, false)) {
      errors.push("公网 UDP 地址格式应类似 203.0.113.10:60207");
    } else if (isUnspecifiedAddress(settings.udpAdvertise)) {
      errors.push("公网 UDP 地址不能使用 0.0.0.0 或 ::");
    }
  }
  if (!isValidSocketPool(settings.socketPool)) {
    errors.push("增强打洞 socket pool 必须为 off 或 2-4");
  }
  if (!settings.diagnosticsUrl.trim()) {
    errors.push("诊断地址不能为空");
  } else {
    try {
      // eslint-disable-next-line no-new
      new URL(settings.diagnosticsUrl);
    } catch {
      errors.push("诊断地址必须是有效 URL");
    }
  }
  if (settings.overlayCidr && !/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(settings.overlayCidr)) {
    errors.push("Overlay CIDR 格式应类似 10.20.0.0/16");
  }
  if (settings.closeBehavior !== "keep-running" && settings.closeBehavior !== "stop-and-quit") {
    errors.push("关闭窗口行为配置无效");
  }
  return errors;
}

function isSocketAddress(value: string, allowPortZero: boolean): boolean {
  const trimmed = value.trim();
  const ipv4 = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
  const ipv6 = trimmed.match(/^\[[0-9a-fA-F:.]+\]:(\d{1,5})$/);
  const portText = ipv4?.[2] ?? ipv6?.[1];
  if (!portText) return false;
  const port = Number(portText);
  if (!Number.isInteger(port) || port < (allowPortZero ? 0 : 1) || port > 65535) return false;
  if (!ipv4) return true;
  return ipv4[1].split(".").every(part => {
    const octet = Number(part);
    return Number.isInteger(octet) && octet >= 0 && octet <= 255;
  });
}

function isUnspecifiedAddress(value: string): boolean {
  const trimmed = value.trim().toLowerCase();
  return trimmed.startsWith("0.0.0.0:") || trimmed.startsWith("[::]:");
}

function normalizeSocketPool(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === "auto" || normalized === "on" || normalized === "true" || normalized === "yes") {
    return "3";
  }
  if (normalized === "off" || normalized === "false" || normalized === "no" || normalized === "none") {
    return "off";
  }
  return normalized;
}

function isValidSocketPool(value: string): boolean {
  const normalized = normalizeSocketPool(value);
  if (normalized === "off") return true;
  const count = Number(normalized);
  return Number.isInteger(count) && count >= 2 && count <= 4;
}
