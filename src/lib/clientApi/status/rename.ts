import { type ApiResult } from "../../../types/client";

import { getSettings } from "../config";
import { normalizeControlServer, readJsonBody } from "../http";
import { appendLog } from "../log";

export async function renamePeerDevice(
  peerId: string,
  deviceNameInput: string
): Promise<ApiResult<{ deviceName: string }>> {
  const settings = getSettings();
  const deviceName = deviceNameInput.trim();
  const fallback = { deviceName };
  if (!deviceName) {
    return { data: fallback, source: "fallback", error: "设备名称不能为空" };
  }
  if ([...deviceName].length > 128) {
    return { data: fallback, source: "fallback", error: "设备名称不能超过 128 个字符" };
  }
  if (!settings.authToken.trim()) {
    return { data: fallback, source: "fallback", error: "登录状态已失效，请重新登录" };
  }

  try {
    const controlServer = normalizeControlServer(settings.controlServer);
    const response = await fetch(
      `${controlServer}/api/v1/devices/${encodeURIComponent(peerId)}`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${settings.authToken}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ device_name: deviceName }),
      }
    );
    const body = await readJsonBody<{ success?: boolean; error?: string }>(response);
    if (!response.ok || !body?.success) {
      let message = body?.error || "设备名称保存失败";
      if (response.status === 401 || response.status === 403) {
        message = "当前账号没有权限修改该设备";
      } else if (response.status === 404) {
        message = "控制服务器暂不支持设备重命名，请先更新服务端";
      }
      appendLog(`device rename failed (${peerId}): ${message}`);
      return { data: fallback, source: "fallback", error: message };
    }
    appendLog(`device renamed (${peerId})`);
    return { data: fallback, source: "live" };
  } catch (error) {
    const message =
      error instanceof TypeError
        ? "无法连接控制服务器，请检查网络后重试"
        : error instanceof Error
          ? error.message
          : typeof error === "string"
            ? error
          : "设备名称保存失败";
    appendLog(`device rename failed (${peerId}): ${message}`);
    return { data: fallback, source: "fallback", error: message };
  }
}
