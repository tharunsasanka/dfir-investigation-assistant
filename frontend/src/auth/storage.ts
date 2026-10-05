type AuthTokenPair = {
  access_token: string
  refresh_token: string
}

const ACCESS_TOKEN_KEY =
  'dfir_access_token'

const REFRESH_TOKEN_KEY =
  'dfir_refresh_token'

export function getAccessToken(): string | null {
  return window.sessionStorage.getItem(
    ACCESS_TOKEN_KEY,
  )
}

export function getRefreshToken(): string | null {
  return window.sessionStorage.getItem(
    REFRESH_TOKEN_KEY,
  )
}

export function saveAuthTokens(
  tokens: AuthTokenPair,
): void {
  window.sessionStorage.setItem(
    ACCESS_TOKEN_KEY,
    tokens.access_token,
  )

  window.sessionStorage.setItem(
    REFRESH_TOKEN_KEY,
    tokens.refresh_token,
  )
}

export function clearAuthTokens(): void {
  window.sessionStorage.removeItem(
    ACCESS_TOKEN_KEY,
  )

  window.sessionStorage.removeItem(
    REFRESH_TOKEN_KEY,
  )
}

export function hasAuthTokens(): boolean {
  return Boolean(
    getRefreshToken(),
  )
}