import axios, {
  type AxiosError,
  type InternalAxiosRequestConfig,
} from 'axios'

import {
  clearAuthTokens,
  getAccessToken,
  getRefreshToken,
  saveAccessToken,
} from '../auth/storage'
import type { AccessTokenResponse } from '../types/auth'

const API_BASE_URL =
  import.meta.env.VITE_API_URL ??
  'http://localhost:8000/api/v1'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
})

const refreshClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
})

type RetryableRequest = InternalAxiosRequestConfig & {
  _retry?: boolean
}

let activeRefreshRequest: Promise<string> | null = null

async function refreshStoredAccessToken(): Promise<string> {
  const refreshToken = getRefreshToken()

  if (!refreshToken) {
    throw new Error('No refresh token is available.')
  }

  if (!activeRefreshRequest) {
    activeRefreshRequest = refreshClient
      .post<AccessTokenResponse>(
        '/auth/refresh',
        {
          refresh_token: refreshToken,
        },
      )
      .then((response) => {
        const newAccessToken =
          response.data.access_token

        saveAccessToken(newAccessToken)

        return newAccessToken
      })
      .finally(() => {
        activeRefreshRequest = null
      })
  }

  return activeRefreshRequest
}

apiClient.interceptors.request.use(
  (
    config: InternalAxiosRequestConfig,
  ): InternalAxiosRequestConfig => {
    const accessToken = getAccessToken()

    if (accessToken) {
      config.headers.Authorization =
        `Bearer ${accessToken}`
    }

    return config
  },
)

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest =
      error.config as RetryableRequest | undefined

    const isAuthenticationRequest =
      originalRequest?.url?.includes('/auth/login') ||
      originalRequest?.url?.includes('/auth/refresh')

    if (
      error.response?.status !== 401 ||
      !originalRequest ||
      originalRequest._retry ||
      isAuthenticationRequest
    ) {
      return Promise.reject(error)
    }

    originalRequest._retry = true

    try {
      const newAccessToken =
        await refreshStoredAccessToken()

      originalRequest.headers.Authorization =
        `Bearer ${newAccessToken}`

      return apiClient(originalRequest)
    } catch (refreshError) {
      clearAuthTokens()

      if (window.location.pathname !== '/login') {
        window.location.assign('/login')
      }

      return Promise.reject(refreshError)
    }
  },
)