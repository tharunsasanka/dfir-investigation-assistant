import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

import {
  getCurrentUser,
  login as requestLogin,
  logout as requestLogout,
} from '../api/auth'
import type {
  LoginRequest,
  User,
} from '../types/auth'
import {
  clearAuthTokens,
  getAccessToken,
  getRefreshToken,
  saveAuthTokens,
} from './storage'

type AuthContextValue = {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  signIn: (
    credentials: LoginRequest,
  ) => Promise<void>
  signOut: () => Promise<void>
  refreshUser: () =>
    Promise<User | null>
}

const AuthContext =
  createContext<
    AuthContextValue | undefined
  >(undefined)

type AuthProviderProps = {
  children: ReactNode
}

export function AuthProvider({
  children,
}: AuthProviderProps) {
  const [
    user,
    setUser,
  ] = useState<User | null>(
    null,
  )

  const [
    isLoading,
    setIsLoading,
  ] = useState(true)

  const clearLocalSession =
    useCallback((): void => {
      clearAuthTokens()
      setUser(null)
    }, [])

  const signOut = useCallback(
    async (): Promise<void> => {
      const refreshToken =
        getRefreshToken()

      try {
        if (refreshToken) {
          await requestLogout({
            refresh_token:
              refreshToken,
          })
        }
      } catch {
        return
      } finally {
        clearLocalSession()
      }
    },
    [
      clearLocalSession,
    ],
  )

  const signIn = useCallback(
    async (
      credentials: LoginRequest,
    ): Promise<void> => {
      const response =
        await requestLogin(
          credentials,
        )

      saveAuthTokens(
        response,
      )

      setUser(
        response.user,
      )
    },
    [],
  )

  const refreshUser = useCallback(
    async (): Promise<
      User | null
    > => {
      const refreshToken =
        getRefreshToken()

      if (!refreshToken) {
        clearLocalSession()
        return null
      }

      try {
        const currentUser =
          await getCurrentUser(
            getAccessToken()
            ?? undefined,
          )

        setUser(
          currentUser,
        )

        return currentUser
      } catch {
        clearLocalSession()
        return null
      }
    },
    [
      clearLocalSession,
    ],
  )

  useEffect(() => {
    let isMounted = true

    async function restoreSession():
    Promise<void> {
      const refreshToken =
        getRefreshToken()

      if (!refreshToken) {
        clearAuthTokens()

        if (isMounted) {
          setUser(null)
          setIsLoading(false)
        }

        return
      }

      try {
        const currentUser =
          await getCurrentUser(
            getAccessToken()
            ?? undefined,
          )

        if (isMounted) {
          setUser(
            currentUser,
          )
        }
      } catch {
        clearAuthTokens()

        if (isMounted) {
          setUser(null)
        }
      } finally {
        if (isMounted) {
          setIsLoading(false)
        }
      }
    }

    void restoreSession()

    return () => {
      isMounted = false
    }
  }, [])

  const value =
    useMemo<AuthContextValue>(
      () => ({
        user,
        isAuthenticated:
          user !== null,
        isLoading,
        signIn,
        signOut,
        refreshUser,
      }),
      [
        user,
        isLoading,
        signIn,
        signOut,
        refreshUser,
      ],
    )

  return (
    <AuthContext.Provider
      value={value}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth():
AuthContextValue {
  const context =
    useContext(
      AuthContext,
    )

  if (
    context === undefined
  ) {
    throw new Error(
      'useAuth must be used inside an AuthProvider.',
    )
  }

  return context
}