import {
  apiClient,
  sessionClient,
} from './client'
import type {
  AccessTokenResponse,
  LoginRequest,
  LogoutRequest,
  LogoutResponse,
  RefreshTokenRequest,
  TokenResponse,
  User,
} from '../types/auth'

export async function login(
  credentials: LoginRequest,
): Promise<TokenResponse> {
  const response =
    await sessionClient
      .post<TokenResponse>(
        '/auth/login',
        credentials,
      )

  return response.data
}

export async function refreshAccessToken(
  request: RefreshTokenRequest,
): Promise<AccessTokenResponse> {
  const response =
    await sessionClient
      .post<AccessTokenResponse>(
        '/auth/refresh',
        request,
      )

  return response.data
}

export async function logout(
  request: LogoutRequest,
): Promise<LogoutResponse> {
  const response =
    await sessionClient
      .post<LogoutResponse>(
        '/auth/logout',
        request,
      )

  return response.data
}

export async function getCurrentUser(
  accessToken?: string,
): Promise<User> {
  const response =
    await apiClient.get<User>(
      '/auth/me',
      accessToken
        ? {
            headers: {
              Authorization:
                `Bearer ${accessToken}`,
            },
          }
        : undefined,
    )

  return response.data
}