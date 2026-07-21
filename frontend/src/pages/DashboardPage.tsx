import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle,
  Archive,
  BriefcaseBusiness,
  ClipboardCheck,
  Database,
  LoaderCircle,
  ShieldAlert,
  X,
} from 'lucide-react'
import {
  useLocation,
  useNavigate,
} from 'react-router-dom'

import { apiClient } from '../api/client'
import { getDashboardCaseSummary } from '../api/dashboard'

type DashboardLocationState = {
  accessDenied?: boolean
  from?: string
}

function formatDate(
  dateValue: string | null,
): string {
  if (!dateValue) {
    return 'No case activity recorded'
  }

  return new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(dateValue))
}

export function DashboardPage() {
  const location = useLocation()
  const navigate = useNavigate()

  const locationState =
    location.state as DashboardLocationState | null

  const accessDenied =
    locationState?.accessDenied === true

  const deniedPath =
    locationState?.from ?? 'the requested page'

  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: async () =>
      (await apiClient.get('/health')).data,
    retry: 1,
  })

  const summaryQuery = useQuery({
    queryKey: ['dashboard', 'case-summary'],
    queryFn: getDashboardCaseSummary,
    retry: 1,
  })

  function dismissAccessDenied(): void {
    navigate(location.pathname, {
      replace: true,
      state: null,
    })
  }

  const summary = summaryQuery.data

  const metrics = [
    {
      label: 'Total cases',
      value: summary?.total_cases,
      icon: BriefcaseBusiness,
    },
    {
      label: 'Active investigations',
      value: summary?.active_cases,
      icon: Database,
    },
    {
      label: 'Critical active cases',
      value: summary?.critical_active_cases,
      icon: AlertTriangle,
    },
    {
      label: 'Awaiting review',
      value: summary?.review_cases,
      icon: ClipboardCheck,
    },
    {
      label: 'Closed cases',
      value: summary?.closed_cases,
      icon: Archive,
    },
  ]

  const totalCases =
    summary?.total_cases ?? 0

  const statusItems = [
    {
      label: 'Active',
      value: summary?.active_cases ?? 0,
    },
    {
      label: 'Awaiting review',
      value: summary?.review_cases ?? 0,
    },
    {
      label: 'Closed',
      value: summary?.closed_cases ?? 0,
    },
    {
      label: 'Critical active',
      value:
        summary?.critical_active_cases ?? 0,
    },
  ]

  return (
    <section>
      {accessDenied && (
        <div
          role="alert"
          className="mb-6 flex items-start justify-between gap-4 rounded-2xl border border-amber-400/30 bg-amber-400/10 p-4 text-amber-100"
        >
          <div className="flex items-start gap-3">
            <ShieldAlert
              size={22}
              className="mt-0.5 shrink-0 text-amber-300"
            />

            <div>
              <p className="font-semibold">
                Access denied
              </p>

              <p className="mt-1 text-sm text-amber-100/80">
                Your account does not have permission
                to open {deniedPath}.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={dismissAccessDenied}
            aria-label="Dismiss access denied message"
            className="rounded-lg p-1 text-amber-200 transition hover:bg-amber-300/10 hover:text-white"
          >
            <X size={18} />
          </button>
        </div>
      )}

      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-cyan">
            Security Operations Overview
          </p>

          <h1 className="mt-1 text-3xl font-bold">
            Investigation Dashboard
          </h1>

          <p className="mt-2 text-sm text-slate-400">
            Live investigation statistics calculated
            from PostgreSQL case records.
          </p>
        </div>

        <div className="glass rounded-xl px-4 py-2 text-sm">
          <span
            className={[
              'mr-2 inline-block h-2 w-2 rounded-full',
              healthQuery.isSuccess
                ? 'bg-emerald-400'
                : healthQuery.isError
                  ? 'bg-red-400'
                  : 'bg-amber-400',
            ].join(' ')}
          />

          API{' '}
          {healthQuery.isSuccess
            ? 'connected'
            : healthQuery.isError
              ? 'unavailable'
              : 'checking'}
        </div>
      </div>

      {summaryQuery.isLoading && (
        <div className="glass mt-8 flex items-center justify-center gap-3 rounded-2xl p-8 text-slate-300">
          <LoaderCircle
            size={20}
            className="animate-spin text-cyan"
          />

          Loading real dashboard statistics...
        </div>
      )}

      {summaryQuery.isError && (
        <div className="glass mt-8 flex items-start gap-3 rounded-2xl border border-red-400/30 p-5 text-red-200">
          <ShieldAlert
            size={22}
            className="mt-0.5 shrink-0"
          />

          <div>
            <p className="font-semibold">
              Dashboard statistics could not be loaded
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              Confirm that the backend and PostgreSQL
              containers are running and that your
              account has the cases.read permission.
            </p>
          </div>
        </div>
      )}

      {summary && (
        <>
          <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            {metrics.map((metric) => {
              const MetricIcon = metric.icon

              return (
                <article
                  key={metric.label}
                  className="glass rounded-2xl p-5"
                >
                  <MetricIcon className="text-cyan" />

                  <p className="mt-5 text-sm text-slate-400">
                    {metric.label}
                  </p>

                  <p className="mt-1 text-3xl font-bold">
                    {metric.value ?? 0}
                  </p>
                </article>
              )
            })}
          </div>

          <div className="mt-6 grid gap-6 xl:grid-cols-[1.4fr_1fr]">
            <article className="glass rounded-2xl p-6">
              <h2 className="font-semibold">
                Investigation status distribution
              </h2>

              <p className="mt-2 text-sm text-slate-400">
                Calculated from the current case
                records.
              </p>

              <div className="mt-6 space-y-5">
                {statusItems.map((item) => {
                  const percentage =
                    totalCases > 0
                      ? Math.min(
                          100,
                          Math.round(
                            (item.value /
                              totalCases) *
                              100,
                          ),
                        )
                      : 0

                  return (
                    <div key={item.label}>
                      <div className="mb-2 flex items-center justify-between gap-4 text-sm">
                        <span className="text-slate-300">
                          {item.label}
                        </span>

                        <span className="font-semibold">
                          {item.value}
                        </span>
                      </div>

                      <div className="h-2 overflow-hidden rounded-full bg-white/5">
                        <div
                          className="h-full rounded-full bg-cyan transition-all"
                          style={{
                            width: `${percentage}%`,
                          }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>

              {totalCases === 0 && (
                <p className="mt-6 rounded-xl border border-white/10 bg-white/5 p-4 text-sm text-slate-400">
                  No case records are currently
                  available for analysis.
                </p>
              )}
            </article>

            <article className="glass rounded-2xl p-6">
              <h2 className="font-semibold">
                Database activity
              </h2>

              <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5">
                <p className="text-sm text-slate-400">
                  Latest case update
                </p>

                <p className="mt-2 font-semibold">
                  {formatDate(
                    summary.latest_case_updated_at,
                  )}
                </p>
              </div>

              <div className="mt-4 rounded-2xl border border-white/10 bg-white/5 p-5">
                <p className="text-sm text-slate-400">
                  Data source
                </p>

                <div className="mt-2 flex items-center gap-2">
                  <Database
                    size={18}
                    className="text-cyan"
                  />

                  <p className="font-semibold">
                    PostgreSQL cases table
                  </p>
                </div>
              </div>

              <div className="mt-4 rounded-2xl border border-white/10 bg-white/5 p-5">
                <p className="text-sm text-slate-400">
                  Dashboard mode
                </p>

                <p className="mt-2 font-semibold text-emerald-300">
                  Live authenticated data
                </p>
              </div>
            </article>
          </div>
        </>
      )}
    </section>
  )
}