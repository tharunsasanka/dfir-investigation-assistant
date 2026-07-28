import {
  useQueryClient,
} from '@tanstack/react-query'
import {
  Activity,
  BriefcaseBusiness,
  LayoutDashboard,
  LoaderCircle,
  LogOut,
  Settings,
  ShieldCheck,
  UserCircle,
} from 'lucide-react'
import {
  useState,
} from 'react'
import {
  NavLink,
  Outlet,
  useNavigate,
} from 'react-router-dom'

import {
  useAuth,
} from '../../auth/AuthContext'
import {
  hasPermission,
} from '../../auth/permissions'

const links = [
  {
    to: '/dashboard',
    label: 'Dashboard',
    icon: LayoutDashboard,
    permission: null,
  },
  {
    to: '/cases',
    label: 'Cases',
    icon: BriefcaseBusiness,
    permission: 'cases.read',
  },
  {
    to: '/investigation',
    label: 'Investigation',
    icon: Activity,
    permission: null,
  },
  {
    to: '/settings',
    label: 'Settings',
    icon: Settings,
    permission: null,
  },
]

export function AppShell() {
  const {
    user,
    signOut,
  } = useAuth()

  const [
    isSigningOut,
    setIsSigningOut,
  ] = useState(false)

  const navigate =
    useNavigate()

  const queryClient =
    useQueryClient()

  const visibleLinks =
    links.filter((link) => {
      if (
        link.permission
        === null
      ) {
        return true
      }

      return hasPermission(
        user,
        link.permission,
      )
    })

  async function handleSignOut():
  Promise<void> {
    if (isSigningOut) {
      return
    }

    setIsSigningOut(true)

    try {
      await signOut()

      queryClient.clear()

      navigate(
        '/login',
        {
          replace: true,
        },
      )
    } finally {
      setIsSigningOut(false)
    }
  }

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[260px_1fr]">
      <aside className="glass flex border-b border-white/10 p-5 lg:min-h-screen lg:flex-col lg:border-b-0 lg:border-r">
        <div className="w-full">
          <div className="mb-8 flex items-center gap-3">
            <div className="rounded-2xl bg-cyan/15 p-2 text-cyan">
              <ShieldCheck />
            </div>

            <div>
              <p className="font-semibold">
                DFIR Assistant
              </p>

              <p className="text-xs text-slate-400">
                Investigation Console
              </p>
            </div>
          </div>

          <nav className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-1">
            {visibleLinks.map(({
              to,
              label,
              icon: Icon,
            }) => (
              <NavLink
                key={to}
                to={to}
                className={({
                  isActive,
                }) =>
                  [
                    'flex items-center gap-3 rounded-xl',
                    'px-3 py-3 text-sm transition',
                    isActive
                      ? 'bg-cyan/15 text-cyan'
                      : 'text-slate-300 hover:bg-white/5 hover:text-white',
                  ].join(' ')
                }
              >
                <Icon size={18} />
                {label}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="mt-auto hidden w-full pt-8 lg:block">
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
            <div className="flex items-start gap-3">
              <UserCircle
                size={24}
                className="mt-0.5 shrink-0 text-cyan"
              />

              <div className="min-w-0">
                <p className="truncate text-sm font-semibold">
                  {user?.full_name ??
                    'Authorized Analyst'}
                </p>

                <p className="mt-1 truncate text-xs text-slate-400">
                  {user?.email}
                </p>

                <p className="mt-2 text-xs capitalize text-cyan">
                  {user?.roles[0]?.name
                    .replace(
                      /_/g,
                      ' ',
                    ) ??
                    'Authenticated user'}
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => {
                void handleSignOut()
              }}
              disabled={
                isSigningOut
              }
              className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-sm text-slate-300 transition hover:border-red-400/30 hover:bg-red-400/10 hover:text-red-200 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSigningOut ? (
                <>
                  <LoaderCircle
                    size={16}
                    className="animate-spin"
                  />
                  Signing out...
                </>
              ) : (
                <>
                  <LogOut size={16} />
                  Sign out
                </>
              )}
            </button>
          </div>
        </div>
      </aside>

      <main className="p-4 sm:p-6 lg:p-8">
        <Outlet />
      </main>
    </div>
  )
}