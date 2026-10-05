import axios, {
  type AxiosError,
  type InternalAxiosRequestConfig,
} from 'axios'

import {
  clearAuthTokens,
  getAccessToken,
  getRefreshToken,
  saveAuthTokens,
} from '../auth/storage'
import type {
  AccessTokenResponse,
} from '../types/auth'

export const API_BASE_URL =
  import.meta.env.VITE_API_URL ??
  'http://localhost:8000/api/v1'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
})

export const sessionClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
})

type RetryableRequest =
  InternalAxiosRequestConfig & {
    _retry?: boolean
  }

let activeRefreshRequest:
  Promise<string> | null = null

async function refreshStoredAccessToken():
Promise<string> {
  const refreshToken =
    getRefreshToken()

  if (!refreshToken) {
    throw new Error(
      'No refresh token is available.',
    )
  }

  if (!activeRefreshRequest) {
    activeRefreshRequest =
      sessionClient
        .post<AccessTokenResponse>(
          '/auth/refresh',
          {
            refresh_token:
              refreshToken,
          },
        )
        .then((response) => {
          saveAuthTokens(
            response.data,
          )

          return (
            response.data
              .access_token
          )
        })
        .finally(() => {
          activeRefreshRequest = null
        })
  }

  return activeRefreshRequest
}

apiClient.interceptors.request.use(
  (
    config:
      InternalAxiosRequestConfig,
  ): InternalAxiosRequestConfig => {
    const accessToken =
      getAccessToken()

    if (accessToken) {
      config.headers.Authorization =
        `Bearer ${accessToken}`
    }

    return config
  },
)

apiClient.interceptors.response.use(
  (response) => response,
  async (
    error: AxiosError,
  ) => {
    const originalRequest =
      error.config as
        RetryableRequest
        | undefined

    const requestUrl =
      originalRequest?.url ?? ''

    const isAuthenticationRequest =
      requestUrl.includes(
        '/auth/login',
      ) ||
      requestUrl.includes(
        '/auth/refresh',
      ) ||
      requestUrl.includes(
        '/auth/logout',
      )

    if (
      error.response?.status !== 401 ||
      !originalRequest ||
      originalRequest._retry ||
      isAuthenticationRequest
    ) {
      return Promise.reject(
        error,
      )
    }

    originalRequest._retry = true

    try {
      const newAccessToken =
        await refreshStoredAccessToken()

      originalRequest.headers.Authorization =
        `Bearer ${newAccessToken}`

      return apiClient(
        originalRequest,
      )
    } catch (refreshError) {
      clearAuthTokens()

      if (
        window.location.pathname
        !== '/login'
      ) {
        window.location.assign(
          '/login',
        )
      }

      return Promise.reject(
        refreshError,
      )
    }
  },
)