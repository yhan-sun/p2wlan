import './styles/app.css'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import { AdminRefreshProvider } from './refresh'
import { installAssetRecovery } from './assetRecovery'

installAssetRecovery()

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AdminRefreshProvider><App /></AdminRefreshProvider>
    </QueryClientProvider>
  </StrictMode>,
)
