import { isAxiosError } from 'axios'
import {
  LoaderCircle,
  LockKeyhole,
  Mail,
  ShieldCheck,
} from 'lucide-react'
import {
  useEffect,
  useState,
  type FormEvent,
} from 'react'
import {
  Link,
  useLocation,
  useNavigate,
} from 'react-router-dom'

import { useAuth } from '../auth/AuthContext'

type LoginLocationState = {
  from?: string
}

export function LoginPage() {
  const {
    isAuthenticated,
    isLoading,
    signIn,
  } = useAuth()

  const navigate = useNavigate()
  const location = useLocation()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const locationState =
    location.state as LoginLocationState | null

  const destination =
    locationState?.from ?? '/dashboard'

  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      navigate(destination, {
        replace: true,
      })
    }
  }, [
    destination,
    isAuthenticated,
    isLoading,
    navigate,
  ])

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault()

    setErrorMessage('')
    setIsSubmitting(true)

    try {
      await signIn({
        email: email.trim(),
        password,
      })

      navigate(destination, {
        replace: true,
      })
    } catch (error) {
      if (isAxiosError(error)) {
        const detail = error.response?.data?.detail

        setErrorMessage(
          typeof detail === 'string'
            ? detail
            : 'Unable to sign in. Check your email and password.',
        )
      } else {
        setErrorMessage(
          'An unexpected authentication error occurred.',
        )
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <main className="grid min-h-screen place-items-center px-6 py-12">
      <form
        onSubmit={handleSubmit}
        className="glass w-full max-w-md rounded-3xl p-8"
      >
        <div className="mb-6 flex items-center gap-3">
          <div className="rounded-2xl bg-cyan/15 p-3 text-cyan">
            <ShieldCheck size={26} />
          </div>

          <div>
            <p className="font-semibold">
              DFIR Assistant
            </p>

            <p className="text-xs text-slate-400">
              Secure Investigation Console
            </p>
          </div>
        </div>

        <h1 className="text-2xl font-bold">
          Secure analyst login
        </h1>

        <p className="mt-2 text-sm text-slate-400">
          Sign in using your authorized investigator account.
        </p>

        {errorMessage && (
          <div
            role="alert"
            className="mt-5 rounded-xl border border-red-400/30 bg-red-400/10 px-4 py-3 text-sm text-red-200"
          >
            {errorMessage}
          </div>
        )}

        <label className="mt-6 block text-sm">
          Email address

          <div className="relative mt-2">
            <Mail
              size={18}
              className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
            />

            <input
              type="email"
              value={email}
              onChange={(event) => {
                setEmail(event.target.value)
              }}
              autoComplete="email"
              required
              disabled={isSubmitting}
              placeholder="analyst@example.com"
              className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 outline-none transition focus:border-cyan/60 disabled:opacity-60"
            />
          </div>
        </label>

        <label className="mt-4 block text-sm">
          Password

          <div className="relative mt-2">
            <LockKeyhole
              size={18}
              className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
            />

            <input
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value)
              }}
              autoComplete="current-password"
              required
              disabled={isSubmitting}
              placeholder="Enter your password"
              className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 outline-none transition focus:border-cyan/60 disabled:opacity-60"
            />
          </div>
        </label>

        <button
          type="submit"
          disabled={isSubmitting}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl bg-cyan py-3 font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? (
            <>
              <LoaderCircle
                size={18}
                className="animate-spin"
              />
              Signing in...
            </>
          ) : (
            'Sign in'
          )}
        </button>

        <Link
          to="/"
          className="mt-5 block text-center text-sm text-slate-400 transition hover:text-cyan"
        >
          Return to landing page
        </Link>
      </form>
    </main>
  )
}