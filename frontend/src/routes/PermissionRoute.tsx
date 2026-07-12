import type { ReactNode } from 'react'
import {
  Navigate,
  useLocation,
} from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'
import { hasPermission } from '../auth/permissions'

type PermissionRouteProps = {
  permission: string
  children: ReactNode
}

export function PermissionRoute({
  permission,
  children,
}: PermissionRouteProps) {
  const { user } = useAuth()
  const location = useLocation()

  if (!hasPermission(user, permission)) {
    return (
      <Navigate
        to="/dashboard"
        replace
        state={{
          accessDenied: true,
          from: `${location.pathname}${location.search}`,
        }}
      />
    )
  }

  return <>{children}</>
}