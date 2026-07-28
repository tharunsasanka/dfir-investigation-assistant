import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import {
  AlertCircle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Edit3,
  KeyRound,
  LoaderCircle,
  LockOpen,
  Plus,
  Save,
  Search,
  ShieldCheck,
  UserCog,
  UserRoundCheck,
  UserRoundX,
  X,
} from 'lucide-react'
import {
  isAxiosError,
} from 'axios'
import {
  useMemo,
  useState,
  type FormEvent,
} from 'react'

import {
  createUser,
  getRoles,
  getUsers,
  unlockUser,
  updateUser,
} from '../../api/administration'
import {
  useAuth,
} from '../../auth/AuthContext'
import {
  hasPermission,
} from '../../auth/permissions'
import type {
  CreateUserRequest,
  UpdateUserRequest,
} from '../../types/administration'
import type {
  User,
} from '../../types/auth'

const PAGE_SIZE = 10

type UserStatusFilter =
  | 'all'
  | 'active'
  | 'inactive'

type ApiErrorBody = {
  detail?:
    | string
    | Array<{
        msg?: string
      }>
}

type UpdateUserVariables = {
  userId: string
  request: UpdateUserRequest
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
    return 'Never'
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

function toggleRole(
  roleIds: string[],
  roleId: string,
): string[] {
  if (
    roleIds.includes(
      roleId,
    )
  ) {
    return roleIds.filter(
      (currentRoleId) =>
        currentRoleId
        !== roleId,
    )
  }

  return [
    ...roleIds,
    roleId,
  ]
}

export function UserAdministrationPanel() {
  const queryClient =
    useQueryClient()

  const {
    user: currentUser,
  } = useAuth()

  const canReadUsers =
    hasPermission(
      currentUser,
      'users.read',
    )

  const canManageUsers =
    hasPermission(
      currentUser,
      'users.manage',
    )

  const canReadRoles =
    hasPermission(
      currentUser,
      'roles.read',
    )

  const [
    page,
    setPage,
  ] = useState(1)

  const [
    searchInput,
    setSearchInput,
  ] = useState('')

  const [
    search,
    setSearch,
  ] = useState('')

  const [
    statusFilter,
    setStatusFilter,
  ] = useState<UserStatusFilter>(
    'all',
  )

  const [
    isCreateOpen,
    setIsCreateOpen,
  ] = useState(false)

  const [
    createEmail,
    setCreateEmail,
  ] = useState('')

  const [
    createFullName,
    setCreateFullName,
  ] = useState('')

  const [
    createPassword,
    setCreatePassword,
  ] = useState('')

  const [
    createRoleIds,
    setCreateRoleIds,
  ] = useState<string[]>([])

  const [
    editingUserId,
    setEditingUserId,
  ] = useState<string | null>(
    null,
  )

  const [
    editEmail,
    setEditEmail,
  ] = useState('')

  const [
    editFullName,
    setEditFullName,
  ] = useState('')

  const [
    editPassword,
    setEditPassword,
  ] = useState('')

  const [
    editRoleIds,
    setEditRoleIds,
  ] = useState<string[]>([])

  const [
    editIsActive,
    setEditIsActive,
  ] = useState(true)

  const [
    editIsSuperuser,
    setEditIsSuperuser,
  ] = useState(false)

  const [
    successMessage,
    setSuccessMessage,
  ] = useState('')

  const activeFilterValue =
    statusFilter === 'all'
      ? undefined
      : statusFilter === 'active'

  const usersQuery = useQuery({
    queryKey: [
      'administration',
      'users',
      {
        page,
        search,
        statusFilter,
      },
    ],

    queryFn: () =>
      getUsers({
        page,
        page_size: PAGE_SIZE,
        search:
          search || undefined,
        is_active:
          activeFilterValue,
      }),

    enabled:
      canReadUsers,
  })

  const rolesQuery = useQuery({
    queryKey: [
      'administration',
      'roles',
    ],

    queryFn: () =>
      getRoles({
        is_active: true,
      }),

    enabled:
      canReadRoles,
  })

  const users = useMemo(
    () =>
      usersQuery.data?.items
      ?? [],
    [
      usersQuery.data?.items,
    ],
  )

  const roles = useMemo(
    () =>
      rolesQuery.data?.items
      ?? [],
    [
      rolesQuery.data?.items,
    ],
  )

  const createMutation =
    useMutation({
      mutationFn:
        (
          request:
            CreateUserRequest,
        ) =>
          createUser(
            request,
          ),

      onSuccess: async (
        createdUser,
      ) => {
        await queryClient.invalidateQueries({
          queryKey: [
            'administration',
            'users',
          ],
        })

        setCreateEmail('')
        setCreateFullName('')
        setCreatePassword('')
        setCreateRoleIds([])
        setIsCreateOpen(false)

        setSuccessMessage(
          `${createdUser.full_name} was created successfully.`,
        )
      },
    })

  const updateMutation =
    useMutation({
      mutationFn:
        ({
          userId,
          request,
        }: UpdateUserVariables) =>
          updateUser(
            userId,
            request,
          ),

      onSuccess: async (
        updatedUser,
      ) => {
        await queryClient.invalidateQueries({
          queryKey: [
            'administration',
            'users',
          ],
        })

        setEditingUserId(null)
        setEditPassword('')

        setSuccessMessage(
          `${updatedUser.full_name} was updated successfully.`,
        )
      },
    })

  const unlockMutation =
    useMutation({
      mutationFn:
        (
          userId: string,
        ) =>
          unlockUser(
            userId,
          ),

      onSuccess: async (
        response,
      ) => {
        await queryClient.invalidateQueries({
          queryKey: [
            'administration',
            'users',
          ],
        })

        setSuccessMessage(
          response.message,
        )
      },
    })

  function handleSearch(
    event:
      FormEvent<HTMLFormElement>,
  ): void {
    event.preventDefault()

    setPage(1)
    setSearch(
      searchInput.trim(),
    )
  }

  function handleCreateSubmit(
    event:
      FormEvent<HTMLFormElement>,
  ): void {
    event.preventDefault()

    createMutation.reset()
    setSuccessMessage('')

    createMutation.mutate({
      email:
        createEmail.trim(),
      full_name:
        createFullName.trim(),
      password:
        createPassword,
      role_ids:
        createRoleIds,
    })
  }

  function beginEditing(
    targetUser: User,
  ): void {
    updateMutation.reset()
    setSuccessMessage('')

    setEditingUserId(
      targetUser.id,
    )

    setEditEmail(
      targetUser.email,
    )

    setEditFullName(
      targetUser.full_name,
    )

    setEditPassword('')

    setEditRoleIds(
      targetUser.roles.map(
        (role) =>
          role.id,
      ),
    )

    setEditIsActive(
      targetUser.is_active,
    )

    setEditIsSuperuser(
      targetUser.is_superuser,
    )
  }

  function closeEditor(): void {
    setEditingUserId(null)
    setEditPassword('')
    updateMutation.reset()
  }

  function handleUpdateSubmit(
    event:
      FormEvent<HTMLFormElement>,
  ): void {
    event.preventDefault()

    if (!editingUserId) {
      return
    }

    updateMutation.reset()
    setSuccessMessage('')

    const request:
      UpdateUserRequest = {
        email:
          editEmail.trim(),
        full_name:
          editFullName.trim(),
        is_active:
          editIsActive,
        role_ids:
          editRoleIds,
    }

    if (
      currentUser?.is_superuser
    ) {
      request.is_superuser =
        editIsSuperuser
    }

    if (
      editPassword.length > 0
    ) {
      request.password =
        editPassword
    }

    updateMutation.mutate({
      userId:
        editingUserId,
      request,
    })
  }

  function handleUnlock(
    userId: string,
  ): void {
    unlockMutation.reset()
    setSuccessMessage('')

    unlockMutation.mutate(
      userId,
    )
  }

  if (!canReadUsers) {
    return (
      <div className="glass rounded-2xl border-amber-400/20 p-6">
        <div className="flex items-start gap-3">
          <ShieldCheck
            size={22}
            className="mt-0.5 shrink-0 text-amber-300"
          />

          <div>
            <h2 className="font-semibold text-white">
              User administration is restricted
            </h2>

            <p className="mt-2 text-sm leading-6 text-slate-400">
              Your account does not have permission
              to view system users.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-cyan">
            Access Control
          </p>

          <h2 className="mt-1 text-2xl font-semibold">
            User administration
          </h2>

          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            Create analyst accounts, assign roles,
            manage account status and unlock users.
          </p>
        </div>

        {canManageUsers && (
          <button
            type="button"
            onClick={() => {
              setIsCreateOpen(
                true,
              )

              setSuccessMessage('')
              createMutation.reset()
            }}
            className="flex items-center gap-2 rounded-xl bg-cyan px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:brightness-110"
          >
            <Plus size={18} />
            Create user
          </button>
        )}
      </div>

      {successMessage && (
        <div className="mt-6 flex items-start gap-3 rounded-xl border border-emerald-400/20 bg-emerald-400/10 p-4 text-sm text-emerald-200">
          <CheckCircle2
            size={19}
            className="mt-0.5 shrink-0"
          />

          {successMessage}
        </div>
      )}

      <div className="glass mt-6 rounded-2xl p-5">
        <form
          onSubmit={
            handleSearch
          }
          className="grid gap-4 md:grid-cols-[1fr_200px_auto]"
        >
          <label className="block">
            <span className="text-sm text-slate-300">
              Search users
            </span>

            <div className="relative mt-2">
              <Search
                size={18}
                className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
              />

              <input
                type="search"
                value={
                  searchInput
                }
                onChange={(
                  event,
                ) => {
                  setSearchInput(
                    event.target.value,
                  )
                }}
                placeholder="Search by name or email"
                className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 outline-none transition focus:border-cyan/60"
              />
            </div>
          </label>

          <label className="block">
            <span className="text-sm text-slate-300">
              Account status
            </span>

            <select
              value={
                statusFilter
              }
              onChange={(
                event,
              ) => {
                setStatusFilter(
                  event.target
                    .value as
                    UserStatusFilter,
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            >
              <option value="all">
                All users
              </option>

              <option value="active">
                Active users
              </option>

              <option value="inactive">
                Inactive users
              </option>
            </select>
          </label>

          <button
            type="submit"
            className="mt-auto flex items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:brightness-110"
          >
            <Search size={18} />
            Search
          </button>
        </form>
      </div>

      {isCreateOpen && (
        <form
          onSubmit={
            handleCreateSubmit
          }
          className="glass mt-6 rounded-2xl p-6"
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="rounded-xl bg-cyan/10 p-3 text-cyan">
                <UserRoundCheck
                  size={21}
                />
              </div>

              <div>
                <h3 className="text-xl font-semibold">
                  Create analyst account
                </h3>

                <p className="mt-1 text-sm text-slate-400">
                  New accounts are created by an
                  authorised administrator.
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => {
                setIsCreateOpen(
                  false,
                )
              }}
              className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:border-cyan/40 hover:text-cyan"
              aria-label="Close create user form"
            >
              <X size={18} />
            </button>
          </div>

          <div className="mt-6 grid gap-5 md:grid-cols-2">
            <label className="block">
              <span className="text-sm text-slate-300">
                Full name
              </span>

              <input
                type="text"
                value={
                  createFullName
                }
                onChange={(
                  event,
                ) => {
                  setCreateFullName(
                    event.target.value,
                  )
                }}
                minLength={2}
                maxLength={150}
                required
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>

            <label className="block">
              <span className="text-sm text-slate-300">
                Email address
              </span>

              <input
                type="email"
                value={
                  createEmail
                }
                onChange={(
                  event,
                ) => {
                  setCreateEmail(
                    event.target.value,
                  )
                }}
                required
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>

            <label className="block md:col-span-2">
              <span className="text-sm text-slate-300">
                Temporary password
              </span>

              <div className="relative mt-2">
                <KeyRound
                  size={18}
                  className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  type="password"
                  value={
                    createPassword
                  }
                  onChange={(
                    event,
                  ) => {
                    setCreatePassword(
                      event.target.value,
                    )
                  }}
                  minLength={12}
                  maxLength={128}
                  required
                  autoComplete="new-password"
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 outline-none transition focus:border-cyan/60"
                />
              </div>
            </label>
          </div>

          <div className="mt-6">
            <p className="text-sm text-slate-300">
              Assigned roles
            </p>

            {rolesQuery.isLoading && (
              <div className="mt-3 flex items-center gap-2 text-sm text-slate-400">
                <LoaderCircle
                  size={17}
                  className="animate-spin"
                />

                Loading roles...
              </div>
            )}

            {!canReadRoles && (
              <p className="mt-3 text-sm text-amber-300">
                Role assignment requires the
                roles.read permission.
              </p>
            )}

            {canReadRoles
              && !rolesQuery.isLoading
              && (
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  {roles.map(
                    (role) => (
                      <label
                        key={role.id}
                        className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/10 bg-white/[0.03] p-4 transition hover:border-cyan/30"
                      >
                        <input
                          type="checkbox"
                          checked={createRoleIds.includes(
                            role.id,
                          )}
                          onChange={() => {
                            setCreateRoleIds(
                              (
                                currentRoleIds,
                              ) =>
                                toggleRole(
                                  currentRoleIds,
                                  role.id,
                                ),
                            )
                          }}
                          className="mt-1"
                        />

                        <div>
                          <p className="font-medium text-white">
                            {role.name}
                          </p>

                          <p className="mt-1 text-xs leading-5 text-slate-500">
                            {role.description}
                          </p>
                        </div>
                      </label>
                    ),
                  )}
                </div>
              )}
          </div>

          {createMutation.isError && (
            <div className="mt-5 flex items-start gap-3 rounded-xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-200">
              <AlertCircle
                size={19}
                className="mt-0.5 shrink-0"
              />

              {getErrorMessage(
                createMutation.error,
              )}
            </div>
          )}

          <button
            type="submit"
            disabled={
              createMutation.isPending
              || createFullName.trim().length
                < 2
              || createEmail.trim().length
                === 0
              || createPassword.length
                < 12
            }
            className="mt-6 flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {createMutation.isPending ? (
              <LoaderCircle
                size={18}
                className="animate-spin"
              />
            ) : (
              <Plus size={18} />
            )}

            Create user
          </button>
        </form>
      )}

      {editingUserId && (
        <form
          onSubmit={
            handleUpdateSubmit
          }
          className="glass mt-6 rounded-2xl border-cyan/20 p-6"
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="rounded-xl bg-violet-400/10 p-3 text-violet-300">
                <UserCog size={21} />
              </div>

              <div>
                <h3 className="text-xl font-semibold">
                  Edit user account
                </h3>

                <p className="mt-1 text-sm text-slate-400">
                  Update identity, roles and
                  account access.
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={
                closeEditor
              }
              className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:border-cyan/40 hover:text-cyan"
              aria-label="Close user editor"
            >
              <X size={18} />
            </button>
          </div>

          <div className="mt-6 grid gap-5 md:grid-cols-2">
            <label className="block">
              <span className="text-sm text-slate-300">
                Full name
              </span>

              <input
                type="text"
                value={
                  editFullName
                }
                onChange={(
                  event,
                ) => {
                  setEditFullName(
                    event.target.value,
                  )
                }}
                minLength={2}
                maxLength={150}
                required
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>

            <label className="block">
              <span className="text-sm text-slate-300">
                Email address
              </span>

              <input
                type="email"
                value={
                  editEmail
                }
                onChange={(
                  event,
                ) => {
                  setEditEmail(
                    event.target.value,
                  )
                }}
                required
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>

            <label className="block md:col-span-2">
              <span className="text-sm text-slate-300">
                New password
              </span>

              <input
                type="password"
                value={
                  editPassword
                }
                onChange={(
                  event,
                ) => {
                  setEditPassword(
                    event.target.value,
                  )
                }}
                minLength={
                  editPassword.length > 0
                    ? 12
                    : undefined
                }
                maxLength={128}
                autoComplete="new-password"
                placeholder="Leave empty to keep the current password"
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            </label>
          </div>

          <div className="mt-6 grid gap-4 md:grid-cols-2">
            <label className="flex items-center justify-between gap-4 rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <div>
                <p className="font-medium text-white">
                  Active account
                </p>

                <p className="mt-1 text-xs text-slate-500">
                  Inactive users cannot sign in.
                </p>
              </div>

              <input
                type="checkbox"
                checked={
                  editIsActive
                }
                disabled={
                  editingUserId
                  === currentUser?.id
                }
                onChange={(
                  event,
                ) => {
                  setEditIsActive(
                    event.target.checked,
                  )
                }}
              />
            </label>

            <label className="flex items-center justify-between gap-4 rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <div>
                <p className="font-medium text-white">
                  Superuser account
                </p>

                <p className="mt-1 text-xs text-slate-500">
                  Grants complete platform access.
                </p>
              </div>

              <input
                type="checkbox"
                checked={
                  editIsSuperuser
                }
                disabled={
                  !currentUser?.is_superuser
                  || editingUserId
                    === currentUser.id
                }
                onChange={(
                  event,
                ) => {
                  setEditIsSuperuser(
                    event.target.checked,
                  )
                }}
              />
            </label>
          </div>

          {canReadRoles && (
            <div className="mt-6">
              <p className="text-sm text-slate-300">
                Assigned roles
              </p>

              <div className="mt-3 grid gap-3 md:grid-cols-2">
                {roles.map(
                  (role) => (
                    <label
                      key={role.id}
                      className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/10 bg-white/[0.03] p-4 transition hover:border-cyan/30"
                    >
                      <input
                        type="checkbox"
                        checked={editRoleIds.includes(
                          role.id,
                        )}
                        onChange={() => {
                          setEditRoleIds(
                            (
                              currentRoleIds,
                            ) =>
                              toggleRole(
                                currentRoleIds,
                                role.id,
                              ),
                          )
                        }}
                        className="mt-1"
                      />

                      <div>
                        <p className="font-medium text-white">
                          {role.name}
                        </p>

                        <p className="mt-1 text-xs leading-5 text-slate-500">
                          {role.description}
                        </p>
                      </div>
                    </label>
                  ),
                )}
              </div>
            </div>
          )}

          {updateMutation.isError && (
            <div className="mt-5 flex items-start gap-3 rounded-xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-200">
              <AlertCircle
                size={19}
                className="mt-0.5 shrink-0"
              />

              {getErrorMessage(
                updateMutation.error,
              )}
            </div>
          )}

          <div className="mt-6 flex flex-wrap gap-3">
            <button
              type="submit"
              disabled={
                updateMutation.isPending
                || editFullName.trim().length
                  < 2
                || editEmail.trim().length
                  === 0
                || (
                  editPassword.length > 0
                  && editPassword.length < 12
                )
              }
              className="flex items-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {updateMutation.isPending ? (
                <LoaderCircle
                  size={18}
                  className="animate-spin"
                />
              ) : (
                <Save size={18} />
              )}

              Save changes
            </button>

            <button
              type="button"
              onClick={
                closeEditor
              }
              className="rounded-xl border border-white/10 px-5 py-3 text-sm font-medium text-slate-300 transition hover:border-cyan/40 hover:text-cyan"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {usersQuery.isLoading && (
        <div className="glass mt-6 flex items-center justify-center gap-3 rounded-2xl p-8 text-slate-300">
          <LoaderCircle
            size={20}
            className="animate-spin text-cyan"
          />

          Loading system users...
        </div>
      )}

      {usersQuery.isError && (
        <div className="glass mt-6 flex items-start gap-3 rounded-2xl border-red-400/30 p-5 text-red-200">
          <AlertCircle
            size={21}
            className="mt-0.5 shrink-0"
          />

          <div>
            <p className="font-semibold">
              Users could not be loaded
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              {getErrorMessage(
                usersQuery.error,
              )}
            </p>
          </div>
        </div>
      )}

      {!usersQuery.isLoading
        && !usersQuery.isError
        && users.length === 0 && (
          <div className="glass mt-6 rounded-2xl p-8 text-center">
            <UserRoundX
              size={34}
              className="mx-auto text-slate-500"
            />

            <h3 className="mt-4 font-semibold text-white">
              No users found
            </h3>

            <p className="mt-2 text-sm text-slate-400">
              No accounts match the current
              search and status filter.
            </p>
          </div>
        )}

      {users.length > 0 && (
        <div className="mt-6 grid gap-4">
          {users.map(
            (systemUser) => {
              const isLocked =
                systemUser.locked_until
                !== null

              const isCurrentUser =
                systemUser.id
                === currentUser?.id

              return (
                <article
                  key={
                    systemUser.id
                  }
                  className="glass rounded-2xl p-5"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-lg font-semibold text-white">
                          {systemUser.full_name}
                        </h3>

                        {isCurrentUser && (
                          <span className="rounded-full border border-cyan/20 bg-cyan/10 px-2.5 py-1 text-xs text-cyan">
                            Your account
                          </span>
                        )}

                        {systemUser.is_superuser && (
                          <span className="rounded-full border border-violet-400/20 bg-violet-400/10 px-2.5 py-1 text-xs text-violet-300">
                            Superuser
                          </span>
                        )}
                      </div>

                      <p className="mt-2 break-all text-sm text-slate-400">
                        {systemUser.email}
                      </p>

                      <p className="mt-1 break-all text-xs text-slate-600">
                        {systemUser.id}
                      </p>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <span
                        className={[
                          'rounded-full border px-3 py-1 text-xs font-medium',
                          systemUser.is_active
                            ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300'
                            : 'border-red-400/20 bg-red-400/10 text-red-300',
                        ].join(' ')}
                      >
                        {systemUser.is_active
                          ? 'Active'
                          : 'Inactive'}
                      </span>

                      {isLocked && (
                        <span className="rounded-full border border-amber-400/20 bg-amber-400/10 px-3 py-1 text-xs font-medium text-amber-300">
                          Locked
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="mt-5 grid gap-4 border-t border-white/10 pt-4 text-sm md:grid-cols-3">
                    <div>
                      <p className="text-xs uppercase tracking-wider text-slate-600">
                        Roles
                      </p>

                      <div className="mt-2 flex flex-wrap gap-2">
                        {systemUser.roles.length > 0 ? (
                          systemUser.roles.map(
                            (role) => (
                              <span
                                key={role.id}
                                className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-300"
                              >
                                {role.name}
                              </span>
                            ),
                          )
                        ) : (
                          <span className="text-xs text-slate-500">
                            No roles assigned
                          </span>
                        )}
                      </div>
                    </div>

                    <div>
                      <p className="text-xs uppercase tracking-wider text-slate-600">
                        Last login
                      </p>

                      <p className="mt-2 text-slate-300">
                        {formatDate(
                          systemUser.last_login_at,
                        )}
                      </p>
                    </div>

                    <div>
                      <p className="text-xs uppercase tracking-wider text-slate-600">
                        Failed attempts
                      </p>

                      <p className="mt-2 text-slate-300">
                        {systemUser.failed_login_attempts}
                      </p>
                    </div>
                  </div>

                  {canManageUsers && (
                    <div className="mt-5 flex flex-wrap gap-3 border-t border-white/10 pt-4">
                      <button
                        type="button"
                        onClick={() => {
                          beginEditing(
                            systemUser,
                          )
                        }}
                        className="flex items-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-sm text-slate-300 transition hover:border-cyan/40 hover:text-cyan"
                      >
                        <Edit3 size={16} />
                        Edit
                      </button>

                      {(isLocked
                        || systemUser.failed_login_attempts
                          > 0) && (
                        <button
                          type="button"
                          onClick={() => {
                            handleUnlock(
                              systemUser.id,
                            )
                          }}
                          disabled={
                            unlockMutation.isPending
                          }
                          className="flex items-center gap-2 rounded-xl border border-amber-400/20 bg-amber-400/10 px-4 py-2 text-sm text-amber-300 transition hover:bg-amber-400/15 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          {unlockMutation.isPending ? (
                            <LoaderCircle
                              size={16}
                              className="animate-spin"
                            />
                          ) : (
                            <LockOpen
                              size={16}
                            />
                          )}

                          Unlock
                        </button>
                      )}
                    </div>
                  )}
                </article>
              )
            },
          )}
        </div>
      )}

      {usersQuery.data
        && usersQuery.data.total > 0 && (
          <div className="glass mt-6 flex flex-wrap items-center justify-between gap-4 rounded-2xl px-5 py-4">
            <p className="text-sm text-slate-400">
              Page{' '}

              <span className="text-white">
                {usersQuery.data.page}
              </span>{' '}

              of{' '}

              <span className="text-white">
                {Math.max(
                  usersQuery.data.pages,
                  1,
                )}
              </span>
            </p>

            <div className="flex gap-2">
              <button
                type="button"
                disabled={
                  page <= 1
                }
                onClick={() => {
                  setPage(
                    (
                      currentPage,
                    ) =>
                      Math.max(
                        currentPage - 1,
                        1,
                      ),
                  )
                }}
                className="flex items-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-sm transition hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronLeft
                  size={17}
                />
                Previous
              </button>

              <button
                type="button"
                disabled={
                  page
                  >= usersQuery.data.pages
                }
                onClick={() => {
                  setPage(
                    (
                      currentPage,
                    ) =>
                      currentPage + 1,
                  )
                }}
                className="flex items-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-sm transition hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
                <ChevronRight
                  size={17}
                />
              </button>
            </div>
          </div>
        )}
    </div>
  )
}