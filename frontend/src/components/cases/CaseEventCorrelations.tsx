import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Clock3,
  Database,
  Gauge,
  GitMerge,
  LoaderCircle,
  Network,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  Target,
  XCircle,
} from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'

import {
  getEventCorrelation,
  listCaseEventCorrelations,
  runCaseEventCorrelation,
} from '../../api/eventCorrelations'
import type {
  EventCorrelationJsonValue,
  EventCorrelationSeverity,
  EventCorrelationType,
} from '../../types/eventCorrelations'

type CaseEventCorrelationsProps = {
  caseId: string
}

const severityOptions: Array<{
  label: string
  value: EventCorrelationSeverity | ''
}> = [
  {
    label: 'All severities',
    value: '',
  },
  {
    label: 'Critical',
    value: 'critical',
  },
  {
    label: 'High',
    value: 'high',
  },
  {
    label: 'Medium',
    value: 'medium',
  },
  {
    label: 'Low',
    value: 'low',
  },
  {
    label: 'Informational',
    value: 'informational',
  },
  {
    label: 'Unknown',
    value: 'unknown',
  },
]

const correlationTypeOptions: Array<{
  label: string
  value: EventCorrelationType | ''
}> = [
  {
    label: 'All correlation types',
    value: '',
  },
  {
    label: 'Shared identity',
    value: 'shared_identity',
  },
  {
    label: 'Shared network',
    value: 'shared_network',
  },
  {
    label: 'Shared host',
    value: 'shared_host',
  },
  {
    label: 'Shared process',
    value: 'shared_process',
  },
  {
    label: 'Authentication sequence',
    value: 'authentication_sequence',
  },
  {
    label: 'MITRE technique',
    value: 'mitre_technique',
  },
  {
    label: 'Temporal cluster',
    value: 'temporal_cluster',
  },
  {
    label: 'Multiple indicators',
    value: 'multi_indicator',
  },
]

function formatLabel(
  value: string,
): string {
  if (!value) {
    return 'Not available'
  }

  return value
    .replace(/_/g, ' ')
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    )
}

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'Not recorded'
  }

  const parsedDate = new Date(value)

  if (
    Number.isNaN(
      parsedDate.getTime(),
    )
  ) {
    return value
  }

  return new Intl.DateTimeFormat(
    'en-GB',
    {
      dateStyle: 'medium',
      timeStyle: 'medium',
    },
  ).format(parsedDate)
}

function formatJsonValue(
  value: EventCorrelationJsonValue,
): string {
  if (value === null) {
    return 'null'
  }

  if (
    typeof value === 'string'
  ) {
    return value
  }

  if (
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value)
  }

  return JSON.stringify(
    value,
    null,
    2,
  )
}

function getSeverityClasses(
  severity: EventCorrelationSeverity,
): string {
  const classes: Record<
    EventCorrelationSeverity,
    string
  > = {
    critical:
      'border-red-400/40 bg-red-400/10 text-red-200',
    high:
      'border-orange-400/40 bg-orange-400/10 text-orange-200',
    medium:
      'border-amber-400/40 bg-amber-400/10 text-amber-200',
    low:
      'border-sky-400/40 bg-sky-400/10 text-sky-200',
    informational:
      'border-emerald-400/40 bg-emerald-400/10 text-emerald-200',
    unknown:
      'border-slate-400/40 bg-slate-400/10 text-slate-300',
  }

  return classes[severity]
}

function getTypeClasses(
  correlationType: EventCorrelationType,
): string {
  const classes: Record<
    EventCorrelationType,
    string
  > = {
    shared_identity:
      'border-violet-400/30 bg-violet-400/10 text-violet-200',
    shared_network:
      'border-cyan/30 bg-cyan/10 text-cyan',
    shared_host:
      'border-sky-400/30 bg-sky-400/10 text-sky-200',
    shared_process:
      'border-fuchsia-400/30 bg-fuchsia-400/10 text-fuchsia-200',
    authentication_sequence:
      'border-red-400/30 bg-red-400/10 text-red-200',
    mitre_technique:
      'border-purple-400/30 bg-purple-400/10 text-purple-200',
    temporal_cluster:
      'border-amber-400/30 bg-amber-400/10 text-amber-200',
    multi_indicator:
      'border-emerald-400/30 bg-emerald-400/10 text-emerald-200',
  }

  return classes[correlationType]
}

function getConfidenceClasses(
  confidence: number,
): string {
  if (confidence >= 90) {
    return 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200'
  }

  if (confidence >= 70) {
    return 'border-cyan/30 bg-cyan/10 text-cyan'
  }

  if (confidence >= 50) {
    return 'border-amber-400/30 bg-amber-400/10 text-amber-200'
  }

  return 'border-slate-400/30 bg-slate-400/10 text-slate-300'
}

function getErrorMessage(
  error: unknown,
): string {
  if (
    isAxiosError(error) &&
    typeof error.response
      ?.data?.detail === 'string'
  ) {
    return error.response.data.detail
  }

  return 'Event correlation data could not be loaded from the server.'
}

export function CaseEventCorrelations({
  caseId,
}: CaseEventCorrelationsProps) {
  const queryClient =
    useQueryClient()

  const [page, setPage] =
    useState(1)

  const [pageSize, setPageSize] =
    useState(10)

  const [
    searchInput,
    setSearchInput,
  ] = useState('')

  const [
    appliedSearch,
    setAppliedSearch,
  ] = useState('')

  const [
    selectedSeverity,
    setSelectedSeverity,
  ] = useState<
    EventCorrelationSeverity | ''
  >('')

  const [
    selectedType,
    setSelectedType,
  ] = useState<
    EventCorrelationType | ''
  >('')

  const [
    minimumConfidence,
    setMinimumConfidence,
  ] = useState('')

  const [
    expandedCorrelationId,
    setExpandedCorrelationId,
  ] = useState<string | null>(
    null,
  )

  const correlationsQuery = useQuery({
    queryKey: [
      'event-correlations',
      'case',
      caseId,
      page,
      pageSize,
      appliedSearch,
      selectedSeverity,
      selectedType,
      minimumConfidence,
    ],

    queryFn: () =>
      listCaseEventCorrelations(
        caseId,
        {
          page,
          page_size: pageSize,
          search:
            appliedSearch ||
            undefined,
          severity:
            selectedSeverity ||
            undefined,
          correlation_type:
            selectedType ||
            undefined,
          min_confidence:
            minimumConfidence
              ? Number(
                  minimumConfidence,
                )
              : undefined,
        },
      ),

    enabled: Boolean(caseId),
  })

  const detailQuery = useQuery({
    queryKey: [
      'event-correlations',
      'detail',
      expandedCorrelationId,
    ],

    queryFn: () => {
      if (
        !expandedCorrelationId
      ) {
        throw new Error(
          'A correlation ID is required.',
        )
      }

      return getEventCorrelation(
        expandedCorrelationId,
      )
    },

    enabled: Boolean(
      expandedCorrelationId,
    ),
  })

  const runMutation = useMutation({
    mutationFn: () =>
      runCaseEventCorrelation(
        caseId,
      ),

    onSuccess: async () => {
      setExpandedCorrelationId(
        null,
      )

      await queryClient.invalidateQueries({
        queryKey: [
          'event-correlations',
          'case',
          caseId,
        ],
      })
    },
  })

  const response =
    correlationsQuery.data

  const correlations =
    response?.items ?? []

  const currentPage =
    response?.page ?? page

  const totalPages =
    response?.pages ?? 0

  const totalCorrelations =
    response?.total ?? 0

  function handleSearchSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    setAppliedSearch(
      searchInput.trim(),
    )

    setPage(1)
  }

  function clearFilters() {
    setSearchInput('')
    setAppliedSearch('')
    setSelectedSeverity('')
    setSelectedType('')
    setMinimumConfidence('')
    setPage(1)
  }

  function toggleCorrelation(
    correlationId: string,
  ) {
    setExpandedCorrelationId(
      (
        currentCorrelationId,
      ) =>
        currentCorrelationId ===
        correlationId
          ? null
          : correlationId,
    )
  }

  const hasActiveFilters = Boolean(
    appliedSearch ||
      selectedSeverity ||
      selectedType ||
      minimumConfidence,
  )

  return (
    <section className="glass rounded-3xl p-6 sm:p-8">
      <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
        <div className="flex items-start gap-3">
          <div className="rounded-2xl bg-violet-400/10 p-3 text-violet-300">
            <GitMerge size={25} />
          </div>

          <div>
            <p className="text-sm text-violet-300">
              Multi-source forensic analysis
            </p>

            <h2 className="mt-1 text-2xl font-bold">
              Cross-Evidence Correlations
            </h2>

            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Connect related activity across
              different evidence items using
              identities, hosts, network
              indicators, processes, event
              timing, authentication sequences,
              and MITRE ATT&CK techniques.
            </p>
          </div>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row">
          <button
            type="button"
            disabled={
              correlationsQuery.isFetching
            }
            onClick={() => {
              void correlationsQuery.refetch()
            }}
            className="flex items-center justify-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-white/20 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              size={17}
              className={
                correlationsQuery.isFetching
                  ? 'animate-spin'
                  : ''
              }
            />

            Refresh
          </button>

          <button
            type="button"
            disabled={
              runMutation.isPending
            }
            onClick={() => {
              runMutation.mutate()
            }}
            className="flex items-center justify-center gap-2 rounded-xl bg-violet-400 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {runMutation.isPending ? (
              <LoaderCircle
                size={17}
                className="animate-spin"
              />
            ) : (
              <Play size={17} />
            )}

            {runMutation.isPending
              ? 'Analysing...'
              : 'Run correlation'}
          </button>
        </div>
      </div>

      {runMutation.isSuccess && (
        <div className="mt-6 rounded-2xl border border-emerald-400/30 bg-emerald-400/10 p-5">
          <div className="flex items-start gap-3">
            <Activity
              size={21}
              className="mt-0.5 shrink-0 text-emerald-300"
            />

            <div>
              <p className="font-semibold text-emerald-200">
                Correlation analysis completed
              </p>

              <div className="mt-3 grid gap-3 text-sm text-emerald-100/80 sm:grid-cols-2 xl:grid-cols-5">
                <p>
                  Created:{' '}
                  <span className="font-semibold text-emerald-100">
                    {
                      runMutation.data
                        .correlations_created
                    }
                  </span>
                </p>

                <p>
                  Updated:{' '}
                  <span className="font-semibold text-emerald-100">
                    {
                      runMutation.data
                        .correlations_updated
                    }
                  </span>
                </p>

                <p>
                  Deleted:{' '}
                  <span className="font-semibold text-emerald-100">
                    {
                      runMutation.data
                        .correlations_deleted
                    }
                  </span>
                </p>

                <p>
                  Events analysed:{' '}
                  <span className="font-semibold text-emerald-100">
                    {
                      runMutation.data
                        .events_analyzed
                    }
                  </span>
                </p>

                <p>
                  Evidence analysed:{' '}
                  <span className="font-semibold text-emerald-100">
                    {
                      runMutation.data
                        .evidence_analyzed
                    }
                  </span>
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {runMutation.isError && (
        <div
          role="alert"
          className="mt-6 flex items-start gap-3 rounded-2xl border border-red-400/30 bg-red-400/10 p-5 text-red-200"
        >
          <XCircle
            size={21}
            className="mt-0.5 shrink-0"
          />

          <div>
            <p className="font-semibold">
              Correlation analysis failed
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              {getErrorMessage(
                runMutation.error,
              )}
            </p>
          </div>
        </div>
      )}

      <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5">
        <form
          onSubmit={
            handleSearchSubmit
          }
          className="grid gap-4 xl:grid-cols-[1.4fr_0.8fr_0.9fr_0.7fr_auto]"
        >
          <label className="text-sm">
            Search correlations

            <div className="relative mt-2">
              <Search
                size={17}
                className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
              />

              <input
                type="search"
                value={searchInput}
                onChange={(event) => {
                  setSearchInput(
                    event.target.value,
                  )
                }}
                placeholder="Rule, title, indicator, tactic..."
                className="w-full rounded-xl border border-white/10 bg-slate-900 py-3 pl-11 pr-4 outline-none transition focus:border-violet-400/60"
              />
            </div>
          </label>

          <label className="text-sm">
            Severity

            <select
              value={
                selectedSeverity
              }
              onChange={(event) => {
                setSelectedSeverity(
                  event.target.value as EventCorrelationSeverity | '',
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-violet-400/60"
            >
              {severityOptions.map(
                (option) => (
                  <option
                    key={
                      option.value ||
                      'all'
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

          <label className="text-sm">
            Correlation type

            <select
              value={selectedType}
              onChange={(event) => {
                setSelectedType(
                  event.target.value as EventCorrelationType | '',
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-violet-400/60"
            >
              {correlationTypeOptions.map(
                (option) => (
                  <option
                    key={
                      option.value ||
                      'all'
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

          <label className="text-sm">
            Minimum confidence

            <select
              value={
                minimumConfidence
              }
              onChange={(event) => {
                setMinimumConfidence(
                  event.target.value,
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-violet-400/60"
            >
              <option value="">
                Any confidence
              </option>

              <option value="50">
                50% or higher
              </option>

              <option value="70">
                70% or higher
              </option>

              <option value="80">
                80% or higher
              </option>

              <option value="90">
                90% or higher
              </option>
            </select>
          </label>

          <div className="flex items-end gap-3">
            <button
              type="submit"
              className="flex min-h-12 items-center justify-center gap-2 rounded-xl bg-violet-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110"
            >
              <Search size={17} />
              Search
            </button>

            {hasActiveFilters && (
              <button
                type="button"
                onClick={
                  clearFilters
                }
                className="flex min-h-12 items-center justify-center rounded-xl border border-white/10 px-4 py-3 text-slate-300 transition hover:border-white/20 hover:text-white"
                aria-label="Clear filters"
              >
                <XCircle
                  size={18}
                />
              </button>
            )}
          </div>
        </form>
      </div>

      <div className="mt-6 flex flex-col gap-4 border-b border-white/10 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="font-semibold">
            {totalCorrelations.toLocaleString()}
            {' '}
            correlation
            {totalCorrelations === 1
              ? ''
              : 's'}
          </p>

          <p className="mt-1 text-sm text-slate-500">
            Page {currentPage}
            {totalPages > 0
              ? ` of ${totalPages}`
              : ''}
          </p>
        </div>

        <label className="text-sm text-slate-400">
          Correlations per page

          <select
            value={pageSize}
            onChange={(event) => {
              setPageSize(
                Number(
                  event.target.value,
                ),
              )

              setPage(1)
            }}
            className="ml-3 rounded-xl border border-white/10 bg-slate-900 px-3 py-2 text-white outline-none"
          >
            <option value={5}>
              5
            </option>

            <option value={10}>
              10
            </option>

            <option value={20}>
              20
            </option>

            <option value={50}>
              50
            </option>
          </select>
        </label>
      </div>

      {correlationsQuery.isPending && (
        <div className="grid min-h-72 place-items-center">
          <div className="text-center">
            <LoaderCircle
              size={32}
              className="mx-auto animate-spin text-violet-300"
            />

            <p className="mt-3 text-sm text-slate-400">
              Loading event correlations...
            </p>
          </div>
        </div>
      )}

      {correlationsQuery.isError && (
        <div
          role="alert"
          className="mt-6 flex items-start gap-3 rounded-2xl border border-red-400/30 bg-red-400/10 p-5 text-red-200"
        >
          <XCircle
            size={22}
            className="mt-0.5 shrink-0"
          />

          <div>
            <p className="font-semibold">
              Correlations unavailable
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              {getErrorMessage(
                correlationsQuery.error,
              )}
            </p>
          </div>
        </div>
      )}

      {!correlationsQuery.isPending &&
        !correlationsQuery.isError &&
        correlations.length === 0 && (
          <div className="grid min-h-72 place-items-center">
            <div className="max-w-md text-center">
              <GitMerge
                size={40}
                className="mx-auto text-slate-600"
              />

              <p className="mt-4 font-semibold">
                No event correlations found
              </p>

              <p className="mt-2 text-sm leading-6 text-slate-500">
                Ingest evidence from multiple
                sources and run correlation
                analysis to connect related
                forensic activity.
              </p>
            </div>
          </div>
        )}

      {!correlationsQuery.isPending &&
        !correlationsQuery.isError &&
        correlations.length > 0 && (
          <div className="mt-5 space-y-5">
            {correlations.map(
              (correlation) => {
                const matchedFields =
                  Object.entries(
                    correlation
                      .matched_fields,
                  )

                const isExpanded =
                  expandedCorrelationId ===
                  correlation.id

                return (
                  <article
                    key={
                      correlation.id
                    }
                    className="rounded-2xl border border-white/10 bg-white/5 p-5 sm:p-6"
                  >
                    <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
                      <div className="flex min-w-0 items-start gap-3">
                        <div className="rounded-xl bg-violet-400/10 p-3 text-violet-300">
                          <Network
                            size={21}
                          />
                        </div>

                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="break-words text-lg font-semibold">
                              {
                                correlation.title
                              }
                            </h3>

                            <span
                              className={[
                                'rounded-full border px-3 py-1 text-xs font-semibold',
                                getSeverityClasses(
                                  correlation.severity,
                                ),
                              ].join(' ')}
                            >
                              {formatLabel(
                                correlation.severity,
                              )}
                            </span>

                            <span
                              className={[
                                'rounded-full border px-3 py-1 text-xs font-semibold',
                                getTypeClasses(
                                  correlation
                                    .correlation_type,
                                ),
                              ].join(' ')}
                            >
                              {formatLabel(
                                correlation
                                  .correlation_type,
                              )}
                            </span>

                            <span
                              className={[
                                'rounded-full border px-3 py-1 text-xs font-semibold',
                                getConfidenceClasses(
                                  correlation.confidence,
                                ),
                              ].join(' ')}
                            >
                              {
                                correlation.confidence
                              }
                              % confidence
                            </span>
                          </div>

                          <p className="mt-3 text-sm leading-6 text-slate-300">
                            {
                              correlation.description
                            }
                          </p>

                          <p className="mt-3 break-all text-xs text-slate-500">
                            Correlation ID:{' '}
                            {
                              correlation.id
                            }
                          </p>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => {
                          toggleCorrelation(
                            correlation.id,
                          )
                        }}
                        className="flex shrink-0 items-center justify-center gap-2 rounded-xl border border-violet-400/30 bg-violet-400/10 px-4 py-2 text-sm font-semibold text-violet-200 transition hover:bg-violet-400/20"
                      >
                        {isExpanded ? (
                          <ChevronUp
                            size={17}
                          />
                        ) : (
                          <ChevronDown
                            size={17}
                          />
                        )}

                        {isExpanded
                          ? 'Hide linked events'
                          : 'View linked events'}
                      </button>
                    </div>

                    <dl className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                        <dt className="text-xs uppercase tracking-wider text-slate-500">
                          Rule ID
                        </dt>

                        <dd className="mt-2 break-words font-semibold text-violet-200">
                          {
                            correlation.rule_id
                          }
                        </dd>
                      </div>

                      <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                        <dt className="text-xs uppercase tracking-wider text-slate-500">
                          Events linked
                        </dt>

                        <dd className="mt-2 font-semibold">
                          {
                            correlation.event_count
                          }
                        </dd>
                      </div>

                      <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                        <dt className="text-xs uppercase tracking-wider text-slate-500">
                          Evidence sources
                        </dt>

                        <dd className="mt-2 font-semibold">
                          {
                            correlation.evidence_count
                          }
                        </dd>
                      </div>

                      <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                        <dt className="text-xs uppercase tracking-wider text-slate-500">
                          Correlation key
                        </dt>

                        <dd className="mt-2 break-all text-sm font-semibold">
                          {correlation
                            .correlation_key ||
                            'Not available'}
                        </dd>
                      </div>
                    </dl>

                    <div className="mt-5 grid gap-4 lg:grid-cols-2">
                      <div className="rounded-2xl border border-white/10 bg-slate-950/30 p-5">
                        <div className="flex items-center gap-2 text-slate-200">
                          <Clock3
                            size={19}
                          />

                          <h4 className="font-semibold">
                            Correlation window
                          </h4>
                        </div>

                        <dl className="mt-4 space-y-4 text-sm">
                          <div>
                            <dt className="text-slate-500">
                              Started
                            </dt>

                            <dd className="mt-1 font-medium">
                              {formatDate(
                                correlation
                                  .window_start,
                              )}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">
                              Ended
                            </dt>

                            <dd className="mt-1 font-medium">
                              {formatDate(
                                correlation
                                  .window_end,
                              )}
                            </dd>
                          </div>
                        </dl>
                      </div>

                      <div className="rounded-2xl border border-purple-400/20 bg-purple-400/5 p-5">
                        <div className="flex items-center gap-2 text-purple-200">
                          <Target
                            size={19}
                          />

                          <h4 className="font-semibold">
                            MITRE ATT&CK
                          </h4>
                        </div>

                        <dl className="mt-4 space-y-4 text-sm">
                          <div>
                            <dt className="text-slate-500">
                              Tactic
                            </dt>

                            <dd className="mt-1 font-semibold text-purple-200">
                              {correlation
                                .mitre_tactic ||
                                'Not mapped'}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">
                              Technique
                            </dt>

                            <dd className="mt-1 font-semibold">
                              {correlation
                                .mitre_technique_id ||
                                'Not mapped'}

                              {correlation
                                .mitre_technique_name
                                ? ` — ${correlation.mitre_technique_name}`
                                : ''}
                            </dd>
                          </div>
                        </dl>
                      </div>
                    </div>

                    <div className="mt-5 rounded-2xl border border-white/10 bg-slate-950/30 p-5">
                      <div className="flex items-center gap-2">
                        <Gauge
                          size={19}
                          className="text-violet-300"
                        />

                        <h4 className="font-semibold">
                          Matched correlation fields
                        </h4>
                      </div>

                      {matchedFields.length ===
                      0 ? (
                        <p className="mt-3 text-sm text-slate-500">
                          No matched fields were
                          recorded.
                        </p>
                      ) : (
                        <dl className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                          {matchedFields.map(
                            ([
                              key,
                              value,
                            ]) => (
                              <div
                                key={key}
                                className="rounded-xl border border-white/10 bg-white/5 p-4"
                              >
                                <dt className="text-xs uppercase tracking-wider text-slate-500">
                                  {formatLabel(
                                    key,
                                  )}
                                </dt>

                                <dd className="mt-2 whitespace-pre-wrap break-words text-sm text-slate-200">
                                  {formatJsonValue(
                                    value,
                                  )}
                                </dd>
                              </div>
                            ),
                          )}
                        </dl>
                      )}
                    </div>

                    {isExpanded && (
                      <div className="mt-5 border-t border-white/10 pt-5">
                        {detailQuery.isPending && (
                          <div className="flex items-center justify-center gap-3 rounded-2xl border border-white/10 bg-slate-950/30 p-8 text-slate-400">
                            <LoaderCircle
                              size={22}
                              className="animate-spin text-violet-300"
                            />

                            Loading linked events...
                          </div>
                        )}

                        {detailQuery.isError && (
                          <div
                            role="alert"
                            className="flex items-start gap-3 rounded-2xl border border-red-400/30 bg-red-400/10 p-5 text-red-200"
                          >
                            <AlertTriangle
                              size={21}
                              className="mt-0.5 shrink-0"
                            />

                            <div>
                              <p className="font-semibold">
                                Linked events unavailable
                              </p>

                              <p className="mt-1 text-sm text-red-200/80">
                                {getErrorMessage(
                                  detailQuery.error,
                                )}
                              </p>
                            </div>
                          </div>
                        )}

                        {detailQuery.isSuccess &&
                          detailQuery.data.id ===
                            correlation.id && (
                            <div>
                              <div className="flex items-center gap-2">
                                <Database
                                  size={19}
                                  className="text-violet-300"
                                />

                                <h4 className="font-semibold">
                                  Linked forensic events
                                </h4>
                              </div>

                              <div className="mt-4 space-y-4">
                                {detailQuery.data.members.map(
                                  (
                                    member,
                                  ) => {
                                    const matchedValues =
                                      Object.entries(
                                        member
                                          .matched_values,
                                      )

                                    return (
                                      <article
                                        key={
                                          member
                                            .membership_id
                                        }
                                        className="rounded-2xl border border-white/10 bg-slate-950/30 p-5"
                                      >
                                        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                                          <div>
                                            <div className="flex flex-wrap items-center gap-2">
                                              <span className="rounded-full border border-violet-400/30 bg-violet-400/10 px-3 py-1 text-xs font-semibold text-violet-200">
                                                Event{' '}
                                                {
                                                  member.position +
                                                  1
                                                }
                                              </span>

                                              <span
                                                className={[
                                                  'rounded-full border px-3 py-1 text-xs font-semibold',
                                                  getSeverityClasses(
                                                    member.severity,
                                                  ),
                                                ].join(' ')}
                                              >
                                                {formatLabel(
                                                  member.severity,
                                                )}
                                              </span>

                                              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs font-semibold text-slate-300">
                                                {formatLabel(
                                                  member.relationship,
                                                )}
                                              </span>
                                            </div>

                                            <p className="mt-3 text-sm leading-6 text-slate-300">
                                              {member.message ||
                                                'No event message was recorded.'}
                                            </p>
                                          </div>

                                          <p className="shrink-0 text-sm text-slate-400">
                                            {formatDate(
                                              member.event_time,
                                            )}
                                          </p>
                                        </div>

                                        <dl className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                                          <div>
                                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                                              Event code
                                            </dt>

                                            <dd className="mt-1 break-words text-sm font-semibold">
                                              {member.event_code ||
                                                'Not available'}
                                            </dd>
                                          </div>

                                          <div>
                                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                                              Host
                                            </dt>

                                            <dd className="mt-1 break-words text-sm font-semibold">
                                              {member.host ||
                                                'Not available'}
                                            </dd>
                                          </div>

                                          <div>
                                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                                              Username
                                            </dt>

                                            <dd className="mt-1 break-words text-sm font-semibold">
                                              {member.username ||
                                                'Not available'}
                                            </dd>
                                          </div>

                                          <div>
                                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                                              Process
                                            </dt>

                                            <dd className="mt-1 break-all text-sm font-semibold">
                                              {member.process_name ||
                                                'Not available'}
                                            </dd>
                                          </div>

                                          <div>
                                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                                              Source IP
                                            </dt>

                                            <dd className="mt-1 break-all text-sm font-semibold">
                                              {member.source_ip ||
                                                'Not available'}
                                            </dd>
                                          </div>

                                          <div>
                                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                                              Destination IP
                                            </dt>

                                            <dd className="mt-1 break-all text-sm font-semibold">
                                              {member.destination_ip ||
                                                'Not available'}
                                            </dd>
                                          </div>

                                          <div>
                                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                                              Source type
                                            </dt>

                                            <dd className="mt-1 break-words text-sm font-semibold">
                                              {formatLabel(
                                                member.source_type,
                                              )}
                                            </dd>
                                          </div>

                                          <div>
                                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                                              Evidence ID
                                            </dt>

                                            <dd className="mt-1 break-all text-xs text-slate-300">
                                              {
                                                member.evidence_id
                                              }
                                            </dd>
                                          </div>
                                        </dl>

                                        {matchedValues.length >
                                          0 && (
                                          <dl className="mt-5 grid gap-3 border-t border-white/10 pt-4 md:grid-cols-2">
                                            {matchedValues.map(
                                              ([
                                                key,
                                                value,
                                              ]) => (
                                                <div
                                                  key={
                                                    key
                                                  }
                                                  className="rounded-xl border border-white/10 bg-white/5 p-3"
                                                >
                                                  <dt className="text-xs uppercase tracking-wider text-slate-500">
                                                    {formatLabel(
                                                      key,
                                                    )}
                                                  </dt>

                                                  <dd className="mt-2 whitespace-pre-wrap break-words text-sm text-slate-200">
                                                    {formatJsonValue(
                                                      value,
                                                    )}
                                                  </dd>
                                                </div>
                                              ),
                                            )}
                                          </dl>
                                        )}

                                        <p className="mt-4 break-all text-xs text-slate-500">
                                          Parsed event ID:{' '}
                                          {
                                            member.parsed_event_id
                                          }
                                        </p>
                                      </article>
                                    )
                                  },
                                )}
                              </div>
                            </div>
                          )}
                      </div>
                    )}

                    <p className="mt-5 text-xs text-slate-500">
                      Created:{' '}
                      {formatDate(
                        correlation.created_at,
                      )}
                    </p>
                  </article>
                )
              },
            )}
          </div>
        )}

      {!correlationsQuery.isPending &&
        !correlationsQuery.isError &&
        totalPages > 1 && (
          <div className="mt-6 flex flex-col gap-4 border-t border-white/10 pt-5 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm text-slate-500">
              Showing page {currentPage} of{' '}
              {totalPages}
            </p>

            <div className="flex gap-3">
              <button
                type="button"
                disabled={
                  currentPage <= 1 ||
                  correlationsQuery.isFetching
                }
                onClick={() => {
                  setPage(
                    Math.max(
                      1,
                      currentPage - 1,
                    ),
                  )
                }}
                className="flex items-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-white/20 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronLeft
                  size={17}
                />

                Previous
              </button>

              <button
                type="button"
                disabled={
                  currentPage >=
                    totalPages ||
                  correlationsQuery.isFetching
                }
                onClick={() => {
                  setPage(
                    Math.min(
                      totalPages,
                      currentPage + 1,
                    ),
                  )
                }}
                className="flex items-center gap-2 rounded-xl border border-violet-400/30 bg-violet-400/10 px-4 py-2 text-sm font-semibold text-violet-200 transition hover:bg-violet-400/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next

                <ChevronRight
                  size={17}
                />
              </button>
            </div>
          </div>
        )}
    </section>
  )
}