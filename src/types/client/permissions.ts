export interface PermissionCheck {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail" | "unknown";
  detail: string;
}

export interface PermissionStatus {
  platform: "macos" | "windows" | "linux" | "unknown" | string;
  canCreateTun: "true" | "false" | "unknown" | string;
  canModifyRoutes: "true" | "false" | "unknown" | string;
  needsElevation: boolean;
  recommendedAction: string;
  sudoCommand?: string | null;
  details: string[];
  checks: PermissionCheck[];
}
