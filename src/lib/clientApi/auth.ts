// Authentication and control-session management for the unified client API.
//
// Split out of `clientApi.ts`.

import type { ApiResult } from "../../types/client";
import type { AuthResponseBody, AuthMode, AuthSession } from "./types";

import { appendLog } from "./log";
import { getSettings, saveSettings } from "./config";
import { normalizeControlServer, readJsonBody } from "./http";

export function clearControlSession(): void {
  const settings = getSettings();
  saveSettings({ ...settings, authToken: "" });
  localStorage.removeItem("token");
}

function zhAuthError(message: string, status?: number): string {
  const normalized = message.toLowerCase();
  if (normalized.includes("failed to fetch") || normalized.includes("load failed") || normalized.includes("networkerror")) {
    return "无法连接控制服务器，请检查服务器地址或网络";
  }
  if (normalized.includes("invalid credentials")) return "邮箱或密码错误";
  if (normalized.includes("invalid email")) return "邮箱格式不正确";
  if (normalized.includes("invalid password")) return "密码不符合要求，至少需要 6 个字符";
  if (normalized.includes("registration failed")) return "注册失败，邮箱可能已存在";
  if (normalized.includes("rate limit")) return "请求过于频繁，请稍后再试";
  if (status === 401) return "认证失败，请检查邮箱和密码";
  if (status === 409) return "账号已存在";
  return message || "控制服务器请求失败";
}

export async function authenticateWithControl(
  mode: AuthMode,
  controlServerInput: string,
  emailInput: string,
  password: string
): Promise<ApiResult<AuthSession>> {
  const controlServer = normalizeControlServer(controlServerInput);
  const email = emailInput.trim().toLowerCase();
  if (!email) throw new Error("请输入邮箱");
  if (!password) throw new Error("请输入密码");
  if (password.length < 6) throw new Error("密码至少需要 6 个字符");

  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 8000);
  try {
    const endpoint = `${controlServer}/api/v1/${mode === "register" ? "register" : "login"}`;
    const res = await fetch(endpoint, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ email, password }),
    });
    const body = await readJsonBody<AuthResponseBody>(res);
    if (!res.ok) {
      throw new Error(zhAuthError(body?.error || "", res.status));
    }
    if (!body?.success || !body.token) {
      throw new Error(body?.error || "控制服务器没有返回有效 token");
    }

    const settings = getSettings();
    const nextSettings = {
      ...settings,
      controlServer,
      authToken: body.token,
    };
    saveSettings(nextSettings);
    localStorage.setItem("token", body.token);
    appendLog(`${mode === "register" ? "registered" : "logged in"} control user (${email})`);
    return {
      data: {
        token: body.token,
        user: body.user,
        controlServer,
      },
      source: "live",
    };
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error("连接控制服务器超时");
    }
    if (err instanceof TypeError) {
      throw new Error("无法连接控制服务器，请检查服务器地址或网络");
    }
    if (err instanceof Error) {
      throw new Error(zhAuthError(err.message));
    }
    throw err;
  } finally {
    window.clearTimeout(timer);
  }
}
