import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useState } from "react";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import NodesPage from "./pages/NodesPage";
import TunnelsPage from "./pages/TunnelsPage";
import SettingsPage from "./pages/SettingsPage";
import Layout from "./components/Layout";

function App() {
  const [token, setToken] = useState<string>(() => localStorage.getItem("token") || "");

  if (!token) {
    return <LoginPage onLogin={setToken} />;
  }

  return (
    <BrowserRouter>
      <Layout onLogout={() => { localStorage.removeItem("token"); setToken(""); }}>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/nodes" element={<NodesPage />} />
          <Route path="/tunnels" element={<TunnelsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

export default App;
