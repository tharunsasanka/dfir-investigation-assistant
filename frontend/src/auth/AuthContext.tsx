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
  refreshAccessToken,
} from '../api/auth'
import type {
  LoginRequest,
  User,
} from '../types/auth'
import {
  clearAuthTokens,
  getAccessToken,
  getRefreshToken,
  saveAccessToken,
  saveAuthTokens,
} from './storage'

type AuthContextValue = {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  signIn: (credentials: LoginRequest) => Promise<void>
  signOut: () => void
}

const AuthContext = createContext<AuthContextValue | undefined>(
  undefined,
)

type AuthProviderProps = {
  children: ReactNode
}

export function AuthProvider({
  children,
}: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const signOut = useCallback((): void => {
    clearAuthTokens()
    setUser(null)
  }, [])

  const signIn = useCallback(
    async (credentials: LoginRequest): Promise<void> => {
      const response = await requestLogin(credentials)

      saveAuthTokens(response)
      setUser(response.user)
    },
    [],
  )

  useEffect(() => {
    let isMounted = true

    async function restoreSession(): Promise<void> {
      const accessToken = getAccessToken()
      const refreshToken = getRefreshToken()

      if (!accessToken || !refreshToken) {
        clearAuthTokens()

        if (isMounted) {
          setUser(null)
          setIsLoading(false)
        }

        return
      }

      try {
        const currentUser = await getCurrentUser(accessToken)

        if (isMounted) {
          setUser(currentUser)
        }
      } catch {
        try {
          const refreshedToken = await refreshAccessToken({
            refresh_token: refreshToken,
          })

          saveAccessToken(refreshedToken.access_token)

          const currentUser = await getCurrentUser(
            refreshedToken.access_token,
          )

          if (isMounted) {
            setUser(currentUser)
          }
        } catch {
          clearAuthTokens()

          if (isMounted) {
            setUser(null)
          }
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

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated: user !== null,
      isLoading,
      signIn,
      signOut,
    }),
    [
      user,
      isLoading,
      signIn,
      signOut,
    ],
  )

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)

  if (context === undefined) {
    throw new Error(
      'useAuth must be used inside an AuthProvider.',
    )
  }

  return context
}