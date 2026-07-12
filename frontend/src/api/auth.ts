import { apiClient } from './client'
import type {
  AccessTokenResponse,
  LoginRequest,
  RefreshTokenRequest,
  TokenResponse,
  User,
} from '../types/auth'

export async function login(
  credentials: LoginRequest,
): Promise<TokenResponse> {
  const response = await apiClient.post<TokenResponse>(
    '/auth/login',
    credentials,
  )

  return response.data
}

export async function refreshAccessToken(
  request: RefreshTokenRequest,
): Promise<AccessTokenResponse> {
  const response = await apiClient.post<AccessTokenResponse>(
    '/auth/refresh',
    request,
  )

  return response.data
}

export async function getCurrentUser(
  accessToken: string,
): Promise<User> {
  const response = await apiClient.get<User>(
    '/auth/me',
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  )

  return response.data
}