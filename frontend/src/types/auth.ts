export type Permission = {
  id: string
  name: string
  description: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export type Role = {
  id: string
  name: string
  description: string
  is_active: boolean
  created_at: string
  updated_at: string
  permissions: Permission[]
}

export type User = {
  id: string
  email: string
  full_name: string
  is_active: boolean
  is_superuser: boolean
  failed_login_attempts: number
  locked_until: string | null
  last_login_at: string | null
  created_at: string
  updated_at: string
  roles: Role[]
}

export type LoginRequest = {
  email: string
  password: string
}

export type TokenResponse = {
  access_token: string
  refresh_token: string
  token_type: 'bearer'
  expires_in: number
  user: User
}

export type AccessTokenResponse = {
  access_token: string
  refresh_token: string
  token_type: 'bearer'
  expires_in: number
}

export type RefreshTokenRequest = {
  refresh_token: string
}

export type LogoutRequest = {
  refresh_token: string
}

export type LogoutResponse = {
  message: string
}