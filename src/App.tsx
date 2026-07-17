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

function App() {
  const [token, setToken] = useState<string>(() => localStorage.getItem("token") || "");
  useWindowLifecycle();

  if (!token) {
    return <LoginPage onLogin={setToken} />;
  }

  return (
    <HashRouter>
      <Layout onLogout={() => { localStorage.removeItem("token"); setToken(""); }}>
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
    </HashRouter>
  );
}

export default App;
