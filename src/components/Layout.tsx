import { NavLink, useNavigate } from "react-router-dom";
import { ReactNode } from "react";
import { Activity, LayoutDashboard, Settings, LogOut, Power, Network } from "lucide-react";
import { StatusPill, healthTone, zhLabel } from "./StatusPill";
import { useClientStatus } from "../hooks/useClientStatus";

interface LayoutProps {
  children: ReactNode;
  onLogout: () => void;
  onRequestQuit: () => void;
}

const navItems = [
  { path: "/dashboard", label: "概览", icon: LayoutDashboard },
  { path: "/nodes", label: "设备", icon: Network },
  { path: "/settings", label: "设置", icon: Settings },
  { path: "/diagnostics", label: "诊断", icon: Activity },
];

function compactOperationLabel(phase: string): string {
  switch (phase) {
    case "authorizing":
      return "授权中";
    case "launching":
    case "waiting_for_daemon":
      return "启动中";
    case "stopping":
      return "停止中";
    case "error":
      return "异常";
    default:
      return "处理中";
  }
}

export default function Layout({ children, onLogout, onRequestQuit }: LayoutProps) {
  const navigate = useNavigate();
  const { daemon, operation } = useClientStatus();
  const operationActive = operation.phase !== "stopped" && operation.phase !== "running";

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <span className="logo-text">p2wlan</span>
          <span className="logo-sub">客户端控制台</span>
        </div>

        <div className="sidebar-status-box">
          <div className="sidebar-status-header">
            <span>守护进程</span>
            <StatusPill
              label={operationActive ? compactOperationLabel(operation.phase) : daemon.lifecycle === "running" ? "在线" : zhLabel(daemon.lifecycle)}
              tone={operationActive ? "warn" : healthTone(daemon.healthStatus)}
              title={operationActive ? operation.message : undefined}
            />
          </div>
          {daemon.virtualIp && <div className="sidebar-status-ip">{daemon.virtualIp}</div>}
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                title={item.label}
                className={({ isActive }) =>
                  `sidebar-link ${isActive ? "active" : ""}`
                }
              >
                <Icon size={16} className="nav-icon" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <button
            className="btn btn-ghost logout-btn full-width"
            onClick={() => {
              onLogout();
              navigate("/login");
            }}
          >
            <LogOut size={14} />
            <span>退出登录</span>
          </button>
          <button
            className="btn btn-ghost quit-btn full-width"
            onClick={onRequestQuit}
          >
            <Power size={14} />
            <span>退出程序</span>
          </button>
        </div>
      </aside>
      <main className="main-content">{children}</main>
    </div>
  );
}
