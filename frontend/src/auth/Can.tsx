import type { ReactNode } from 'react'

import { useAuth } from './AuthContext'
import {
  hasAllPermissions,
  hasAnyPermission,
  hasPermission,
} from './permissions'

type CanProps = {
  children: ReactNode
  permission?: string
  anyOf?: string[]
  allOf?: string[]
  fallback?: ReactNode
}

export function Can({
  children,
  permission,
  anyOf,
  allOf,
  fallback = null,
}: CanProps) {
  const { user } = useAuth()

  let isAllowed = true

  if (permission) {
    isAllowed =
      isAllowed &&
      hasPermission(user, permission)
  }

  if (anyOf && anyOf.length > 0) {
    isAllowed =
      isAllowed &&
      hasAnyPermission(user, anyOf)
  }

  if (allOf && allOf.length > 0) {
    isAllowed =
      isAllowed &&
      hasAllPermissions(user, allOf)
  }

  if (!isAllowed) {
    return <>{fallback}</>
  }

  return <>{children}</>
}