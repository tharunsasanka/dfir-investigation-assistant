import { LoaderCircle } from 'lucide-react'
import {
  Navigate,
  Outlet,
  useLocation,
} from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'

export function ProtectedRoute() {
  const {
    isAuthenticated,
    isLoading,
  } = useAuth()

  const location = useLocation()

  if (isLoading) {
    return (
      <main className="grid min-h-screen place-items-center p-6">
        <div className="glass flex items-center gap-3 rounded-2xl px-6 py-4 text-slate-300">
          <LoaderCircle
            className="animate-spin text-cyan"
            size={20}
          />
          <span>Restoring secure session...</span>
        </div>
      </main>
    )
  }

  if (!isAuthenticated) {
    return (
      <Navigate
        to="/login"
        replace
        state={{
          from: `${location.pathname}${location.search}`,
        }}
      />
    )
  }

  return <Outlet />
}