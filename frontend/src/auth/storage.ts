import type { TokenResponse } from '../types/auth'

const ACCESS_TOKEN_KEY = 'dfir_access_token'
const REFRESH_TOKEN_KEY = 'dfir_refresh_token'

export function getAccessToken(): string | null {
  return sessionStorage.getItem(ACCESS_TOKEN_KEY)
}

export function getRefreshToken(): string | null {
  return sessionStorage.getItem(REFRESH_TOKEN_KEY)
}

export function saveAuthTokens(
  tokens: Pick<TokenResponse, 'access_token' | 'refresh_token'>,
): void {
  sessionStorage.setItem(
    ACCESS_TOKEN_KEY,
    tokens.access_token,
  )

  sessionStorage.setItem(
    REFRESH_TOKEN_KEY,
    tokens.refresh_token,
  )
}

export function saveAccessToken(accessToken: string): void {
  sessionStorage.setItem(
    ACCESS_TOKEN_KEY,
    accessToken,
  )
}

export function clearAuthTokens(): void {
  sessionStorage.removeItem(ACCESS_TOKEN_KEY)
  sessionStorage.removeItem(REFRESH_TOKEN_KEY)
}

export function hasAuthTokens(): boolean {
  return Boolean(
    getAccessToken() && getRefreshToken(),
  )
}