import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from 'react-router-dom'
import { clearAdminToken, getAdminToken } from './api'
import { ConnectionHealthPage } from './ConnectionHealthPage'
import { ConnectionsPage } from './ConnectionsPage'
import { AccountDetailPage } from './features/accounts/AccountDetailPage'
import { AccountsPage } from './features/accounts/AccountsPage'
import { Login } from './features/auth/LoginPage'
import { DevicesPage } from './features/devices/DevicesPage'
import { NetworksPage } from './features/networks/NetworksPage'
import { Dashboard } from './features/overview/OverviewPage'
import { RelationshipsPage } from './features/relationships/RelationshipsPage'
import { SystemPage } from './features/system/SystemPage'
import { Shell } from './layout/AppShell'

function AuthenticatedApp({ onLogout }: { onLogout: () => void }) {
  return <BrowserRouter basename="/admin"><Routes>
    <Route element={<Shell onLogout={onLogout} />}>
      <Route index element={<Dashboard />} />
      <Route path="accounts" element={<AccountsPage />} />
      <Route path="accounts/:id" element={<AccountDetailPage />} />
      <Route path="relationships" element={<RelationshipsPage />} />
      <Route path="topology" element={<Navigate to="/relationships" replace />} />
      <Route path="connections" element={<ConnectionsPage />} />
      <Route path="devices" element={<DevicesPage />} />
      <Route path="networks" element={<NetworksPage />} />
      <Route path="health" element={<ConnectionHealthPage />} />
      <Route path="system" element={<SystemPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>
  </Routes></BrowserRouter>
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(Boolean(getAdminToken()))
  const queryClient = useQueryClient()

  useEffect(() => {
    const unauthorized = () => {
      clearAdminToken()
      queryClient.clear()
      setAuthenticated(false)
    }
    window.addEventListener('p2wlan:unauthorized', unauthorized)
    return () => window.removeEventListener('p2wlan:unauthorized', unauthorized)
  }, [queryClient])

  return authenticated
    ? <AuthenticatedApp onLogout={() => setAuthenticated(false)} />
    : <Login onSuccess={() => setAuthenticated(true)} />
}
