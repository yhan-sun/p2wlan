// Shared types and constants for the unified client API.

export const SETTINGS_KEY = "p2wlan.client.settings";
export const LOG_KEY = "p2wlan.client.logs";
export const MAX_LOG_LINES = 400;
export const CONTROL_STALE_AFTER_SECS = 30;
export const RELAY_PRESENTATION_FRESH_MS = 30_000;

export type AuthMode = "login" | "register";

export interface AuthUser {
  id?: string;
  email?: string;
  created_at?: number;
  createdAt?: number;
}

export interface AuthSession {
  token: string;
  user?: AuthUser;
  controlServer: string;
}

export interface AuthResponseBody {
  success?: boolean;
  token?: string;
  user?: AuthUser;
  error?: string;
}
