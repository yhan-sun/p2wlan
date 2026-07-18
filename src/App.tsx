import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import NodesPage from "./pages/NodesPage";
import TunnelsPage from "./pages/TunnelsPage";
import SettingsPage from "./pages/SettingsPage";
import DiagnosticsPage from "./pages/DiagnosticsPage";
import OnboardingPage from "./pages/OnboardingPage";
import Layout from "./components/Layout";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { useState } from "react";
import { useWindowLifecycle } from "./hooks/useWindowLifecycle";
import { ClientStatusProvider } from "./hooks/useClientStatus";
import { clearControlSession } from "./lib/clientApi";
import WindowChrome, { detectDesktopPlatform } from "./components/WindowChrome";

function App() {
  const [token, setToken] = useState<string>(() => localStorage.getItem("token") || "");
  const platform = detectDesktopPlatform();
  useWindowLifecycle();

  return (
    <div className={`app-frame app-frame-${platform}`}>
      <WindowChrome platform={platform} />
      <div className="app-content">
        {!token ? (
          <LoginPage onLogin={setToken} />
        ) : (
          <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <ClientStatusProvider>
              <Layout
                onLogout={() => {
                  clearControlSession();
                  setToken("");
                }}
              >
                <Routes>
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/login" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<DashboardPage />} />
                  <Route path="/nodes" element={<NodesPage />} />
                  <Route path="/tunnels" element={<TunnelsPage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="/diagnostics" element={<DiagnosticsPage />} />
                  <Route path="/onboarding" element={<OnboardingPage />} />
                </Routes>
              </Layout>
            </ClientStatusProvider>
          </HashRouter>
        )}
      </div>
    </div>
  );
}

export default App;
