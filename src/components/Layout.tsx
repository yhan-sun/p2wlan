import { NavLink, useNavigate } from "react-router-dom";
import { ReactNode } from "react";

interface LayoutProps {
  children: ReactNode;
  onLogout: () => void;
}

const navItems = [
  { path: "/dashboard", label: "Dashboard", icon: "📊" },
  { path: "/nodes", label: "Nodes", icon: "🖥️" },
  { path: "/tunnels", label: "Tunnels", icon: "🔗" },
  { path: "/settings", label: "Settings", icon: "⚙️" },
];

export default function Layout({ children, onLogout }: LayoutProps) {
  const navigate = useNavigate();

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-logo">P2PNet</div>
        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `sidebar-link ${isActive ? "active" : ""}`
              }
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <button
            className="btn btn-ghost"
            onClick={() => {
              onLogout();
              navigate("/login");
            }}
            style={{ width: "100%" }}
          >
            Logout
          </button>
        </div>
      </aside>
      <main className="main-content">{children}</main>
    </div>
  );
}
