import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import './styles.css'
import './polish.css'
import './connections.css'
import './connection-health.css'
import './theme.css'
import App from './App'
import { AdminRefreshProvider } from './refresh'

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
