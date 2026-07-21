import type { User } from '../types/auth'

export function getUserPermissionNames(
  user: User | null,
): Set<string> {
  if (!user) {
    return new Set<string>()
  }

  const permissionNames = new Set<string>()

  for (const role of user.roles) {
    if (!role.is_active) {
      continue
    }

    for (const permission of role.permissions) {
      if (permission.is_active) {
        permissionNames.add(permission.name)
      }
    }
  }

  return permissionNames
}

export function hasPermission(
  user: User | null,
  permissionName: string,
): boolean {
  if (!user) {
    return false
  }

  if (user.is_superuser) {
    return true
  }

  return getUserPermissionNames(user).has(
    permissionName,
  )
}

export function hasAnyPermission(
  user: User | null,
  permissionNames: string[],
): boolean {
  return permissionNames.some((permissionName) =>
    hasPermission(user, permissionName),
  )
}

export function hasAllPermissions(
  user: User | null,
  permissionNames: string[],
): boolean {
  return permissionNames.every((permissionName) =>
    hasPermission(user, permissionName),
  )
}