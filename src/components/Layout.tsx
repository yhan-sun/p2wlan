import { NavLink, useNavigate } from "react-router-dom";
import { ReactNode } from "react";
import { Activity, LayoutDashboard, Settings, LogOut, Power, Network } from "lucide-react";
import { quitApp } from "../lib/clientApi";
import { StatusPill, healthTone, zhLabel } from "./StatusPill";
import { useClientStatus } from "../hooks/useClientStatus";

interface LayoutProps {
  children: ReactNode;
  onLogout: () => void;
}

const navItems = [
  { path: "/dashboard", label: "概览", icon: LayoutDashboard },
  { path: "/nodes", label: "设备", icon: Network },
  { path: "/settings", label: "设置", icon: Settings },
  { path: "/diagnostics", label: "诊断", icon: Activity },
];

export default function Layout({ children, onLogout }: LayoutProps) {
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
              label={operationActive ? operation.message : daemon.lifecycle === "running" ? "在线" : zhLabel(daemon.lifecycle)}
              tone={operationActive ? "warn" : healthTone(daemon.healthStatus)}
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
            onClick={() => {
              void quitApp();
            }}
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
