import {
  keepPreviousData,
  useQuery,
} from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  Filter,
  FolderSearch,
  LoaderCircle,
  Plus,
  Search,
  ShieldAlert,
} from 'lucide-react'
import {
  useState,
  type FormEvent,
} from 'react'
import { Link } from 'react-router-dom'

import { getCases } from '../api/cases'
import { Can } from '../auth/Can'
import { CreateCaseForm } from '../components/cases/CreateCaseForm'
import { OpenInvestigationWorkspaceButton } from '../components/cases/OpenInvestigationWorkspaceButton'
import type {
  CaseSeverity,
  CaseStatus,
} from '../types/case'

const PAGE_SIZE = 10

const severityOptions: Array<{
  value: '' | CaseSeverity
  label: string
}> = [
  {
    value: '',
    label: 'All severities',
  },
  {
    value: 'low',
    label: 'Low',
  },
  {
    value: 'medium',
    label: 'Medium',
  },
  {
    value: 'high',
    label: 'High',
  },
  {
    value: 'critical',
    label: 'Critical',
  },
]

const statusOptions: Array<{
  value: '' | CaseStatus
  label: string
}> = [
  {
    value: '',
    label: 'All statuses',
  },
  {
    value: 'open',
    label: 'Open',
  },
  {
    value: 'investigating',
    label: 'Investigating',
  },
  {
    value: 'review',
    label: 'Review',
  },
  {
    value: 'closed',
    label: 'Closed',
  },
]

function formatDate(
  dateValue: string,
): string {
  return new Intl.DateTimeFormat(
    'en-GB',
    {
      dateStyle: 'medium',
      timeStyle: 'short',
    },
  ).format(
    new Date(dateValue),
  )
}

function formatLabel(
  value: string,
): string {
  return value
    .replace(/_/g, ' ')
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    )
}

function getSeverityClasses(
  severity: CaseSeverity,
): string {
  const classes: Record<
    CaseSeverity,
    string
  > = {
    low: [
      'border-emerald-400/30',
      'bg-emerald-400/10',
      'text-emerald-300',
    ].join(' '),

    medium: [
      'border-sky-400/30',
      'bg-sky-400/10',
      'text-sky-300',
    ].join(' '),

    high: [
      'border-amber-400/30',
      'bg-amber-400/10',
      'text-amber-300',
    ].join(' '),

    critical: [
      'border-red-400/30',
      'bg-red-400/10',
      'text-red-300',
    ].join(' '),
  }

  return classes[severity]
}

function getStatusClasses(
  status: CaseStatus,
): string {
  const classes: Record<
    CaseStatus,
    string
  > = {
    open: 'text-cyan',
    investigating: 'text-amber-300',
    review: 'text-violet-300',
    closed: 'text-emerald-300',
  }

  return classes[status]
}

export function CasesPage() {
  const [
    searchInput,
    setSearchInput,
  ] = useState('')

  const [
    search,
    setSearch,
  ] = useState('')

  const [
    severity,
    setSeverity,
  ] = useState<
    '' | CaseSeverity
  >('')

  const [
    caseStatus,
    setCaseStatus,
  ] = useState<
    '' | CaseStatus
  >('')

  const [
    page,
    setPage,
  ] = useState(1)

  const [
    isCreateFormOpen,
    setIsCreateFormOpen,
  ] = useState(false)

  const casesQuery = useQuery({
    queryKey: [
      'cases',
      {
        page,
        search,
        severity,
        status: caseStatus,
      },
    ],

    queryFn: () =>
      getCases({
        page,
        page_size: PAGE_SIZE,
        search:
          search || undefined,
        severity:
          severity || undefined,
        status:
          caseStatus || undefined,
      }),

    placeholderData:
      keepPreviousData,
  })

  function handleSearch(
    event: FormEvent<HTMLFormElement>,
  ): void {
    event.preventDefault()

    setPage(1)
    setSearch(
      searchInput.trim(),
    )
  }

  function clearFilters(): void {
    setSearchInput('')
    setSearch('')
    setSeverity('')
    setCaseStatus('')
    setPage(1)
  }

  const data =
    casesQuery.data

  const cases =
    data?.items ?? []

  const totalPages =
    data?.pages ?? 0

  const hasActiveFilters =
    Boolean(
      search
      || severity
      || caseStatus,
    )

  return (
    <section>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-cyan">
            Investigation Management
          </p>

          <h1 className="mt-1 text-3xl font-bold">
            Cases
          </h1>

          <p className="mt-2 text-sm text-slate-400">
            View, search, filter, and create
            investigation cases stored in
            PostgreSQL.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="glass rounded-xl px-4 py-2 text-sm text-slate-300">
            Total cases:{' '}

            <span className="font-semibold text-white">
              {data?.total ?? 0}
            </span>
          </div>

          <Can permission="cases.create">
            <button
              type="button"
              onClick={() => {
                setIsCreateFormOpen(
                  true,
                )
              }}
              className="flex items-center gap-2 rounded-xl bg-cyan px-4 py-2 text-sm font-semibold text-slate-950 transition hover:brightness-110"
            >
              <Plus size={18} />
              Create case
            </button>
          </Can>
        </div>
      </div>

      <div className="glass mt-8 rounded-2xl p-5">
        <form
          onSubmit={
            handleSearch
          }
          className="grid gap-4 lg:grid-cols-[1fr_190px_190px_auto]"
        >
          <label className="block">
            <span className="text-sm text-slate-300">
              Search cases
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
                    event.target
                      .value,
                  )
                }}
                placeholder="Search title or description"
                className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 outline-none transition focus:border-cyan/60"
              />
            </div>
          </label>

          <label className="block">
            <span className="text-sm text-slate-300">
              Severity
            </span>

            <select
              value={severity}
              onChange={(
                event,
              ) => {
                setSeverity(
                  event.target
                    .value as
                    | ''
                    | CaseSeverity,
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            >
              {severityOptions.map(
                (option) => (
                  <option
                    key={
                      option.value
                      || 'all-severities'
                    }
                    value={
                      option.value
                    }
                  >
                    {option.label}
                  </option>
                ),
              )}
            </select>
          </label>

          <label className="block">
            <span className="text-sm text-slate-300">
              Status
            </span>

            <select
              value={
                caseStatus
              }
              onChange={(
                event,
              ) => {
                setCaseStatus(
                  event.target
                    .value as
                    | ''
                    | CaseStatus,
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            >
              {statusOptions.map(
                (option) => (
                  <option
                    key={
                      option.value
                      || 'all-statuses'
                    }
                    value={
                      option.value
                    }
                  >
                    {option.label}
                  </option>
                ),
              )}
            </select>
          </label>

          <button
            type="submit"
            className="mt-auto flex items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950 transition hover:brightness-110"
          >
            <Filter size={18} />
            Apply
          </button>
        </form>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={
              clearFilters
            }
            className="mt-4 text-sm text-slate-400 transition hover:text-cyan"
          >
            Clear all filters
          </button>
        )}
      </div>

      {casesQuery.isLoading && (
        <div className="glass mt-6 flex items-center justify-center gap-3 rounded-2xl p-8 text-slate-300">
          <LoaderCircle
            size={20}
            className="animate-spin text-cyan"
          />

          Loading investigation
          cases...
        </div>
      )}

      {casesQuery.isError && (
        <div className="glass mt-6 flex items-start gap-3 rounded-2xl border-red-400/30 p-5 text-red-200">
          <ShieldAlert
            size={22}
            className="mt-0.5 shrink-0"
          />

          <div>
            <p className="font-semibold">
              Cases could not be
              loaded
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              Check that the backend
              and PostgreSQL containers
              are running, then refresh
              the page.
            </p>
          </div>
        </div>
      )}

      {!casesQuery.isLoading
        && !casesQuery.isError
        && cases.length === 0 && (
          <div className="glass mt-6 grid place-items-center rounded-2xl p-10 text-center">
            <FolderSearch
              size={38}
              className="text-slate-500"
            />

            <h2 className="mt-4 font-semibold">
              No matching cases
            </h2>

            <p className="mt-2 max-w-md text-sm text-slate-400">
              No PostgreSQL records
              match the selected search
              and filters.
            </p>
          </div>
        )}

      {cases.length > 0 && (
        <div className="mt-6 grid gap-4">
          {cases.map(
            (
              investigationCase,
            ) => (
              <article
                key={
                  investigationCase.id
                }
                className="glass rounded-2xl p-5 transition duration-200 hover:-translate-y-0.5 hover:border-cyan/40 hover:shadow-[0_20px_60px_rgba(34,211,238,0.08)]"
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0">
                    <Link
                      to={`/cases/${investigationCase.id}`}
                      className="group inline-flex max-w-full items-center gap-2"
                      aria-label={`Open case ${investigationCase.title}`}
                    >
                      <h2 className="truncate text-lg font-semibold transition group-hover:text-cyan">
                        {
                          investigationCase
                            .title
                        }
                      </h2>

                      <ArrowUpRight
                        size={17}
                        className="shrink-0 text-slate-500 transition group-hover:text-cyan"
                      />
                    </Link>

                    <p className="mt-2 break-all text-xs text-slate-500">
                      Case ID:{' '}
                      {
                        investigationCase
                          .id
                      }
                    </p>
                  </div>

                  <span
                    className={[
                      'rounded-full border px-3 py-1 text-xs font-medium',
                      getSeverityClasses(
                        investigationCase
                          .severity,
                      ),
                    ].join(' ')}
                  >
                    {formatLabel(
                      investigationCase
                        .severity,
                    )}
                  </span>
                </div>

                <p className="mt-4 text-sm leading-6 text-slate-300">
                  {
                    investigationCase
                      .description
                    || (
                      'No case description '
                      + 'has been provided.'
                    )
                  }
                </p>

                <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-white/10 pt-4 text-xs">
                  <div className="flex items-center gap-2">
                    <AlertTriangle
                      size={15}
                      className={getStatusClasses(
                        investigationCase
                          .status,
                      )}
                    />

                    <span
                      className={getStatusClasses(
                        investigationCase
                          .status,
                      )}
                    >
                      {formatLabel(
                        investigationCase
                          .status,
                      )}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center justify-end gap-3">
                    <div className="text-slate-500">
                      Created:{' '}

                      {formatDate(
                        investigationCase
                          .created_at,
                      )}
                    </div>

                    <OpenInvestigationWorkspaceButton
                      caseId={
                        investigationCase
                          .id
                      }
                      compact
                    />
                  </div>
                </div>
              </article>
            ),
          )}
        </div>
      )}

      {data
        && data.total > 0 && (
          <div className="glass mt-6 flex flex-wrap items-center justify-between gap-4 rounded-2xl px-5 py-4">
            <p className="text-sm text-slate-400">
              Page{' '}

              <span className="text-white">
                {data.page}
              </span>{' '}

              of{' '}

              <span className="text-white">
                {Math.max(
                  totalPages,
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
                        1,
                        currentPage
                        - 1,
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
                  totalPages === 0
                  || page
                    >= totalPages
                }
                onClick={() => {
                  setPage(
                    (
                      currentPage,
                    ) =>
                      currentPage
                      + 1,
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

      {isCreateFormOpen && (
        <CreateCaseForm
          onClose={() => {
            setIsCreateFormOpen(
              false,
            )
          }}
        />
      )}
    </section>
  )
}