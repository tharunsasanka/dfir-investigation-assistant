import {
  useMutation,
  useQueryClient,
} from '@tanstack/react-query'
import {
  AlertCircle,
  CheckCircle2,
  Clock3,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Mail,
  Save,
  ShieldCheck,
  UserCog,
  UserRound,
  UsersRound,
} from 'lucide-react'
import {
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from 'react'
import {
  isAxiosError,
} from 'axios'
import {
  useNavigate,
} from 'react-router-dom'

import {
  changePassword,
  updateProfile,
} from '../api/administration'
import {
  useAuth,
} from '../auth/AuthContext'
import {
  hasPermission,
} from '../auth/permissions'
import {
  UserAdministrationPanel,
} from '../components/settings/UserAdministrationPanel'

type SettingsTab =
  | 'profile'
  | 'security'
  | 'administration'

type ApiErrorBody = {
  detail?:
    | string
    | Array<{
        msg?: string
      }>
}

function getErrorMessage(
  error: unknown,
): string {
  if (
    isAxiosError<ApiErrorBody>(
      error,
    )
  ) {
    const detail =
      error.response?.data?.detail

    if (
      typeof detail === 'string'
    ) {
      return detail
    }

    if (
      Array.isArray(detail)
      && detail.length > 0
    ) {
      const messages = detail
        .map(
          (item) =>
            item.msg,
        )
        .filter(
          (
            message,
          ): message is string =>
            Boolean(message),
        )

      if (
        messages.length > 0
      ) {
        return messages.join(' ')
      }
    }
  }

  if (
    error instanceof Error
  ) {
    return error.message
  }

  return 'The request could not be completed.'
}

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'Not available'
  }

  const date = new Date(value)

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return 'Not available'
  }

  return new Intl.DateTimeFormat(
    'en-GB',
    {
      dateStyle: 'medium',
      timeStyle: 'short',
    },
  ).format(date)
}

export function SettingsPage() {
  const queryClient =
    useQueryClient()

  const navigate =
    useNavigate()

  const {
    user,
    refreshUser,
    signOut,
  } = useAuth()

  const [
    activeTab,
    setActiveTab,
  ] = useState<SettingsTab>(
    'profile',
  )

  const [
    fullName,
    setFullName,
  ] = useState(
    user?.full_name ?? '',
  )

  const [
    currentPassword,
    setCurrentPassword,
  ] = useState('')

  const [
    newPassword,
    setNewPassword,
  ] = useState('')

  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState('')

  const [
    profileSuccess,
    setProfileSuccess,
  ] = useState('')

  const [
    passwordSuccess,
    setPasswordSuccess,
  ] = useState('')

  const canReadUsers =
    hasPermission(
      user,
      'users.read',
    )

  useEffect(() => {
    setFullName(
      user?.full_name ?? '',
    )
  }, [
    user?.full_name,
  ])

  useEffect(() => {
    if (
      activeTab
      === 'administration'
      && !canReadUsers
    ) {
      setActiveTab(
        'profile',
      )
    }
  }, [
    activeTab,
    canReadUsers,
  ])

  const activeRoles = useMemo(
    () =>
      user?.roles.filter(
        (role) =>
          role.is_active,
      ) ?? [],
    [
      user?.roles,
    ],
  )

  const permissionCount = useMemo(
    () => {
      const permissions =
        new Set<string>()

      for (
        const role
        of activeRoles
      ) {
        for (
          const permission
          of role.permissions
        ) {
          if (
            permission.is_active
          ) {
            permissions.add(
              permission.name,
            )
          }
        }
      }

      return permissions.size
    },
    [
      activeRoles,
    ],
  )

  const profileMutation =
    useMutation({
      mutationFn:
        updateProfile,

      onSuccess: async () => {
        await refreshUser()

        setProfileSuccess(
          'Your profile was updated successfully.',
        )
      },
    })

  const passwordMutation =
    useMutation({
      mutationFn:
        changePassword,

      onSuccess: async (
        response,
      ) => {
        setCurrentPassword('')
        setNewPassword('')
        setConfirmPassword('')

        setPasswordSuccess(
          response.message,
        )

        await signOut()

        queryClient.clear()

        navigate(
          '/login',
          {
            replace: true,
          },
        )
      },
    })

  function handleProfileSubmit(
    event:
      FormEvent<HTMLFormElement>,
  ): void {
    event.preventDefault()

    profileMutation.reset()
    setProfileSuccess('')

    profileMutation.mutate({
      full_name:
        fullName.trim(),
    })
  }

  function handlePasswordSubmit(
    event:
      FormEvent<HTMLFormElement>,
  ): void {
    event.preventDefault()

    passwordMutation.reset()
    setPasswordSuccess('')

    passwordMutation.mutate({
      current_password:
        currentPassword,
      new_password:
        newPassword,
      confirm_password:
        confirmPassword,
    })
  }

  if (!user) {
    return null
  }

  return (
    <section>
      <div>
        <p className="text-sm text-cyan">
          Account and Platform
        </p>

        <h1 className="mt-1 text-3xl font-bold">
          Settings
        </h1>

        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
          Manage your analyst profile,
          account security and authorised
          platform users.
        </p>
      </div>

      <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="glass rounded-2xl p-5">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-cyan/10 p-3 text-cyan">
              <UserRound size={20} />
            </div>

            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">
                Account
              </p>

              <p className="mt-1 font-semibold text-white">
                {user.is_active
                  ? 'Active'
                  : 'Inactive'}
              </p>
            </div>
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-violet-400/10 p-3 text-violet-300">
              <UsersRound size={20} />
            </div>

            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">
                Active roles
              </p>

              <p className="mt-1 font-semibold text-white">
                {activeRoles.length}
              </p>
            </div>
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-emerald-400/10 p-3 text-emerald-300">
              <ShieldCheck size={20} />
            </div>

            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">
                Permissions
              </p>

              <p className="mt-1 font-semibold text-white">
                {user.is_superuser
                  ? 'All'
                  : permissionCount}
              </p>
            </div>
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-amber-400/10 p-3 text-amber-300">
              <Clock3 size={20} />
            </div>

            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">
                Last login
              </p>

              <p className="mt-1 text-sm font-semibold text-white">
                {formatDate(
                  user.last_login_at,
                )}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="mt-8 flex flex-wrap gap-2 rounded-2xl border border-white/10 bg-white/[0.03] p-2">
        <button
          type="button"
          onClick={() => {
            setActiveTab(
              'profile',
            )
          }}
          className={[
            'flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium transition',
            activeTab
            === 'profile'
              ? 'bg-cyan text-slate-950'
              : 'text-slate-400 hover:bg-white/5 hover:text-white',
          ].join(' ')}
        >
          <UserRound size={17} />
          Profile
        </button>

        <button
          type="button"
          onClick={() => {
            setActiveTab(
              'security',
            )
          }}
          className={[
            'flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium transition',
            activeTab
            === 'security'
              ? 'bg-cyan text-slate-950'
              : 'text-slate-400 hover:bg-white/5 hover:text-white',
          ].join(' ')}
        >
          <LockKeyhole size={17} />
          Password and security
        </button>

        {canReadUsers && (
          <button
            type="button"
            onClick={() => {
              setActiveTab(
                'administration',
              )
            }}
            className={[
              'flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium transition',
              activeTab
              === 'administration'
                ? 'bg-cyan text-slate-950'
                : 'text-slate-400 hover:bg-white/5 hover:text-white',
            ].join(' ')}
          >
            <UserCog size={17} />
            User administration
          </button>
        )}
      </div>

      {activeTab === 'profile' && (
        <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_360px]">
          <form
            onSubmit={
              handleProfileSubmit
            }
            className="glass rounded-2xl p-6"
          >
            <div className="flex items-start gap-3">
              <div className="rounded-xl bg-cyan/10 p-3 text-cyan">
                <UserRound size={21} />
              </div>

              <div>
                <h2 className="text-xl font-semibold">
                  Analyst profile
                </h2>

                <p className="mt-1 text-sm text-slate-400">
                  Update the name displayed
                  throughout the investigation
                  platform.
                </p>
              </div>
            </div>

            <label className="mt-6 block">
              <span className="text-sm text-slate-300">
                Full name
              </span>

              <input
                type="text"
                value={fullName}
                onChange={(
                  event,
                ) => {
                  setFullName(
                    event.target.value,
                  )
                }}
                minLength={2}
                maxLength={150}
                required
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>

            <label className="mt-5 block">
              <span className="text-sm text-slate-300">
                Email address
              </span>

              <div className="relative mt-2">
                <Mail
                  size={18}
                  className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  type="email"
                  value={user.email}
                  readOnly
                  className="w-full cursor-not-allowed rounded-xl border border-white/10 bg-white/[0.03] py-3 pl-11 pr-4 text-slate-500 outline-none"
                />
              </div>

              <p className="mt-2 text-xs text-slate-500">
                Email changes are controlled
                by a system administrator.
              </p>
            </label>

            {profileSuccess && (
              <div className="mt-5 flex items-start gap-3 rounded-xl border border-emerald-400/20 bg-emerald-400/10 p-4 text-sm text-emerald-200">
                <CheckCircle2
                  size={19}
                  className="mt-0.5 shrink-0"
                />

                {profileSuccess}
              </div>
            )}

            {profileMutation.isError && (
              <div className="mt-5 flex items-start gap-3 rounded-xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-200">
                <AlertCircle
                  size={19}
                  className="mt-0.5 shrink-0"
                />

                {getErrorMessage(
                  profileMutation.error,
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={
                profileMutation.isPending
                || fullName.trim().length
                  < 2
              }
              className="mt-6 flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {profileMutation.isPending ? (
                <LoaderCircle
                  size={18}
                  className="animate-spin"
                />
              ) : (
                <Save size={18} />
              )}

              Save profile
            </button>
          </form>

          <div className="glass rounded-2xl p-6">
            <h2 className="font-semibold">
              Account information
            </h2>

            <div className="mt-5 space-y-4 text-sm">
              <div>
                <p className="text-slate-500">
                  User ID
                </p>

                <p className="mt-1 break-all text-slate-300">
                  {user.id}
                </p>
              </div>

              <div>
                <p className="text-slate-500">
                  Account type
                </p>

                <p className="mt-1 text-slate-300">
                  {user.is_superuser
                    ? 'Superuser'
                    : 'Standard user'}
                </p>
              </div>

              <div>
                <p className="text-slate-500">
                  Created
                </p>

                <p className="mt-1 text-slate-300">
                  {formatDate(
                    user.created_at,
                  )}
                </p>
              </div>

              <div>
                <p className="text-slate-500">
                  Updated
                </p>

                <p className="mt-1 text-slate-300">
                  {formatDate(
                    user.updated_at,
                  )}
                </p>
              </div>
            </div>

            <div className="mt-6 border-t border-white/10 pt-5">
              <p className="text-sm font-medium text-white">
                Assigned roles
              </p>

              <div className="mt-3 flex flex-wrap gap-2">
                {activeRoles.length > 0 ? (
                  activeRoles.map(
                    (role) => (
                      <span
                        key={role.id}
                        className="rounded-full border border-cyan/20 bg-cyan/10 px-3 py-1 text-xs text-cyan"
                      >
                        {role.name}
                      </span>
                    ),
                  )
                ) : (
                  <span className="text-sm text-slate-500">
                    No active roles assigned
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'security' && (
        <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_360px]">
          <form
            onSubmit={
              handlePasswordSubmit
            }
            className="glass rounded-2xl p-6"
          >
            <div className="flex items-start gap-3">
              <div className="rounded-xl bg-amber-400/10 p-3 text-amber-300">
                <KeyRound size={21} />
              </div>

              <div>
                <h2 className="text-xl font-semibold">
                  Change password
                </h2>

                <p className="mt-1 text-sm text-slate-400">
                  Confirm your current password
                  before setting a new one.
                </p>
              </div>
            </div>

            <label className="mt-6 block">
              <span className="text-sm text-slate-300">
                Current password
              </span>

              <input
                type="password"
                value={
                  currentPassword
                }
                onChange={(
                  event,
                ) => {
                  setCurrentPassword(
                    event.target.value,
                  )
                }}
                autoComplete="current-password"
                required
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>

            <label className="mt-5 block">
              <span className="text-sm text-slate-300">
                New password
              </span>

              <input
                type="password"
                value={newPassword}
                onChange={(
                  event,
                ) => {
                  setNewPassword(
                    event.target.value,
                  )
                }}
                autoComplete="new-password"
                minLength={12}
                maxLength={128}
                required
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>

            <label className="mt-5 block">
              <span className="text-sm text-slate-300">
                Confirm new password
              </span>

              <input
                type="password"
                value={
                  confirmPassword
                }
                onChange={(
                  event,
                ) => {
                  setConfirmPassword(
                    event.target.value,
                  )
                }}
                autoComplete="new-password"
                minLength={12}
                maxLength={128}
                required
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>

            {passwordSuccess && (
              <div className="mt-5 flex items-start gap-3 rounded-xl border border-emerald-400/20 bg-emerald-400/10 p-4 text-sm text-emerald-200">
                <CheckCircle2
                  size={19}
                  className="mt-0.5 shrink-0"
                />

                {passwordSuccess}
              </div>
            )}

            {passwordMutation.isError && (
              <div className="mt-5 flex items-start gap-3 rounded-xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-200">
                <AlertCircle
                  size={19}
                  className="mt-0.5 shrink-0"
                />

                {getErrorMessage(
                  passwordMutation.error,
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={
                passwordMutation.isPending
                || currentPassword.length
                  === 0
                || newPassword.length
                  < 12
                || confirmPassword.length
                  < 12
              }
              className="mt-6 flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {passwordMutation.isPending ? (
                <LoaderCircle
                  size={18}
                  className="animate-spin"
                />
              ) : (
                <KeyRound size={18} />
              )}

              Change password
            </button>
          </form>

          <div className="glass rounded-2xl p-6">
            <h2 className="font-semibold">
              Password requirements
            </h2>

            <div className="mt-5 space-y-3 text-sm text-slate-400">
              <div className="flex gap-2">
                <CheckCircle2
                  size={17}
                  className="mt-0.5 shrink-0 text-cyan"
                />

                At least 12 characters
              </div>

              <div className="flex gap-2">
                <CheckCircle2
                  size={17}
                  className="mt-0.5 shrink-0 text-cyan"
                />

                At least one uppercase letter
              </div>

              <div className="flex gap-2">
                <CheckCircle2
                  size={17}
                  className="mt-0.5 shrink-0 text-cyan"
                />

                At least one lowercase letter
              </div>

              <div className="flex gap-2">
                <CheckCircle2
                  size={17}
                  className="mt-0.5 shrink-0 text-cyan"
                />

                At least one number
              </div>

              <div className="flex gap-2">
                <CheckCircle2
                  size={17}
                  className="mt-0.5 shrink-0 text-cyan"
                />

                At least one special character
              </div>

              <div className="flex gap-2">
                <CheckCircle2
                  size={17}
                  className="mt-0.5 shrink-0 text-cyan"
                />

                Must differ from the current password
              </div>
            </div>

            <div className="mt-6 rounded-xl border border-amber-400/20 bg-amber-400/10 p-4">
              <div className="flex items-start gap-3">
                <LockKeyhole
                  size={19}
                  className="mt-0.5 shrink-0 text-amber-300"
                />

                <p className="text-sm leading-6 text-amber-100/80">
                  Use a unique password that
                  is not shared with another
                  service or investigation
                  platform.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab
        === 'administration'
        && canReadUsers && (
          <div className="mt-6">
            <UserAdministrationPanel />
          </div>
        )}
    </section>
  )
}