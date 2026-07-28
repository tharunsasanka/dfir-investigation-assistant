import type {
  Permission,
  Role,
  User,
} from './auth'

export type UserListResponse = {
  items: User[]
  total: number
  page: number
  page_size: number
  pages: number
}

export type RoleListResponse = {
  items: Role[]
  total: number
}

export type PermissionListResponse = {
  items: Permission[]
  total: number
}

export type UserUnlockResponse = {
  user: User
  unlocked_at: string
  message: string
}

export type UserListParams = {
  page?: number
  page_size?: number
  search?: string
  is_active?: boolean
}

export type RoleListParams = {
  is_active?: boolean
}

export type PermissionListParams = {
  is_active?: boolean
}

export type CreateUserRequest = {
  email: string
  full_name: string
  password: string
  role_ids: string[]
}

export type UpdateUserRequest = {
  email?: string
  full_name?: string
  password?: string
  is_active?: boolean
  is_superuser?: boolean
  role_ids?: string[]
}

export type ProfileUpdateRequest = {
  full_name: string
}

export type PasswordChangeRequest = {
  current_password: string
  new_password: string
  confirm_password: string
}

export type MessageResponse = {
  message: string
}