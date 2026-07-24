import { useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Gauge,
  LoaderCircle,
  RefreshCw,
  Search,
  ShieldAlert,
  Target,
  XCircle,
} from 'lucide-react'
import {
  FormEvent,
  useState,
} from 'react'

import {
  listCaseSecurityFindings,
} from '../../api/securityFindings'
import type {
  JsonValue,
  SecurityFindingSeverity,
} from '../../types/securityFindings'

type CaseSecurityFindingsProps = {
  caseId: string
}

const severityOptions: Array<{
  label: string
  value: SecurityFindingSeverity | ''
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
  value: JsonValue,
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
  severity: SecurityFindingSeverity,
): string {
  const classes: Record<
    SecurityFindingSeverity,
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

function getConfidenceClasses(
  confidence: number,
): string {
  if (confidence >= 90) {
    return (
      'border-emerald-400/30 ' +
      'bg-emerald-400/10 ' +
      'text-emerald-200'
    )
  }

  if (confidence >= 70) {
    return (
      'border-cyan/30 ' +
      'bg-cyan/10 ' +
      'text-cyan'
    )
  }

  if (confidence >= 50) {
    return (
      'border-amber-400/30 ' +
      'bg-amber-400/10 ' +
      'text-amber-200'
    )
  }

  return (
    'border-slate-400/30 ' +
    'bg-slate-400/10 ' +
    'text-slate-300'
  )
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

  return (
    'Security findings could not ' +
    'be loaded from the server.'
  )
}

export function CaseSecurityFindings({
  caseId,
}: CaseSecurityFindingsProps) {
  const [page, setPage] =
    useState(1)

  const [pageSize, setPageSize] =
    useState(10)

  const [searchInput, setSearchInput] =
    useState('')

  const [appliedSearch, setAppliedSearch] =
    useState('')

  const [
    selectedSeverity,
    setSelectedSeverity,
  ] =
    useState<
      SecurityFindingSeverity | ''
    >('')

  const [
    minimumConfidence,
    setMinimumConfidence,
  ] = useState('')

  const findingsQuery = useQuery({
    queryKey: [
      'security-findings',
      'case',
      caseId,
      page,
      pageSize,
      appliedSearch,
      selectedSeverity,
      minimumConfidence,
    ],

    queryFn: () =>
      listCaseSecurityFindings(
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

  const response =
    findingsQuery.data

  const findings =
    response?.items ?? []

  const currentPage =
    response?.page ?? page

  const totalPages =
    response?.pages ?? 0

  const totalFindings =
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
    setMinimumConfidence('')
    setPage(1)
  }

  const hasActiveFilters = Boolean(
    appliedSearch ||
      selectedSeverity ||
      minimumConfidence,
  )

  return (
    <section className="glass rounded-3xl p-6 sm:p-8">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex items-start gap-3">
          <div className="rounded-2xl bg-red-400/10 p-3 text-red-300">
            <ShieldAlert size={25} />
          </div>

          <div>
            <p className="text-sm text-red-300">
              Automated forensic detections
            </p>

            <h2 className="mt-1 text-2xl font-bold">
              Security Findings
            </h2>

            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Review suspicious activity,
              confidence levels, MITRE ATT&CK
              mappings, and indicators linked
              directly to parsed evidence events.
            </p>
          </div>
        </div>

        <button
          type="button"
          disabled={
            findingsQuery.isFetching
          }
          onClick={() => {
            void findingsQuery.refetch()
          }}
          className="flex items-center justify-center gap-2 rounded-xl border border-red-400/30 bg-red-400/10 px-4 py-2 text-sm font-semibold text-red-200 transition hover:bg-red-400/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw
            size={17}
            className={
              findingsQuery.isFetching
                ? 'animate-spin'
                : ''
            }
          />

          Refresh
        </button>
      </div>

      <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5">
        <form
          onSubmit={
            handleSearchSubmit
          }
          className="grid gap-4 xl:grid-cols-[1.5fr_0.8fr_0.7fr_auto]"
        >
          <label className="text-sm">
            Search findings

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
                placeholder="Rule, title, event code, tactic..."
                className="w-full rounded-xl border border-white/10 bg-slate-900 py-3 pl-11 pr-4 outline-none transition focus:border-red-400/60"
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
                  event.target.value as SecurityFindingSeverity | '',
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-red-400/60"
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
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-red-400/60"
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
              className="flex min-h-12 items-center justify-center gap-2 rounded-xl bg-red-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110"
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
            {totalFindings.toLocaleString()}
            {' '}
            security finding
            {totalFindings === 1
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
          Findings per page

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

      {findingsQuery.isPending && (
        <div className="grid min-h-72 place-items-center">
          <div className="text-center">
            <LoaderCircle
              size={32}
              className="mx-auto animate-spin text-red-300"
            />

            <p className="mt-3 text-sm text-slate-400">
              Loading security findings...
            </p>
          </div>
        </div>
      )}

      {findingsQuery.isError && (
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
              Findings unavailable
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              {getErrorMessage(
                findingsQuery.error,
              )}
            </p>
          </div>
        </div>
      )}

      {!findingsQuery.isPending &&
        !findingsQuery.isError &&
        findings.length === 0 && (
          <div className="grid min-h-72 place-items-center">
            <div className="max-w-md text-center">
              <ShieldAlert
                size={38}
                className="mx-auto text-slate-600"
              />

              <p className="mt-4 font-semibold">
                No security findings found
              </p>

              <p className="mt-2 text-sm leading-6 text-slate-500">
                No detections match the
                current filters. Findings are
                created when supported evidence
                logs are ingested.
              </p>
            </div>
          </div>
        )}

      {!findingsQuery.isPending &&
        !findingsQuery.isError &&
        findings.length > 0 && (
          <div className="mt-5 space-y-5">
            {findings.map(
              (finding) => {
                const indicators =
                  Object.entries(
                    finding.indicators,
                  )

                return (
                  <article
                    key={finding.id}
                    className="rounded-2xl border border-white/10 bg-white/5 p-5 sm:p-6"
                  >
                    <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
                      <div className="flex min-w-0 items-start gap-3">
                        <div className="rounded-xl bg-red-400/10 p-3 text-red-300">
                          <AlertTriangle
                            size={21}
                          />
                        </div>

                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="break-words text-lg font-semibold">
                              {
                                finding.title
                              }
                            </h3>

                            <span
                              className={[
                                'rounded-full border px-3 py-1 text-xs font-semibold',
                                getSeverityClasses(
                                  finding.severity,
                                ),
                              ].join(' ')}
                            >
                              {formatLabel(
                                finding.severity,
                              )}
                            </span>

                            <span
                              className={[
                                'rounded-full border px-3 py-1 text-xs font-semibold',
                                getConfidenceClasses(
                                  finding.confidence,
                                ),
                              ].join(' ')}
                            >
                              {
                                finding.confidence
                              }
                              % confidence
                            </span>
                          </div>

                          <p className="mt-3 text-sm leading-6 text-slate-300">
                            {
                              finding.description
                            }
                          </p>

                          <p className="mt-3 break-all text-xs text-slate-500">
                            Finding ID:{' '}
                            {finding.id}
                          </p>
                        </div>
                      </div>

                      <div className="shrink-0 text-sm text-slate-400 xl:text-right">
                        <p>
                          Event time
                        </p>

                        <p className="mt-1 font-medium text-slate-300">
                          {formatDate(
                            finding.event_time,
                          )}
                        </p>
                      </div>
                    </div>

                    <dl className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                        <dt className="text-xs uppercase tracking-wider text-slate-500">
                          Rule ID
                        </dt>

                        <dd className="mt-2 break-words font-semibold text-red-200">
                          {
                            finding.rule_id
                          }
                        </dd>
                      </div>

                      <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                        <dt className="text-xs uppercase tracking-wider text-slate-500">
                          Event code
                        </dt>

                        <dd className="mt-2 break-words font-semibold">
                          {finding.event_code ||
                            'Not available'}
                        </dd>
                      </div>

                      <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                        <dt className="text-xs uppercase tracking-wider text-slate-500">
                          Source type
                        </dt>

                        <dd className="mt-2 font-semibold">
                          {formatLabel(
                            finding.source_type,
                          )}
                        </dd>
                      </div>

                      <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                        <dt className="text-xs uppercase tracking-wider text-slate-500">
                          Event index
                        </dt>

                        <dd className="mt-2 font-semibold">
                          {
                            finding.event_index
                          }
                        </dd>
                      </div>
                    </dl>

                    <div className="mt-5 grid gap-4 lg:grid-cols-2">
                      <div className="rounded-2xl border border-violet-400/20 bg-violet-400/5 p-5">
                        <div className="flex items-center gap-2 text-violet-200">
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

                            <dd className="mt-1 font-semibold text-violet-200">
                              {finding.mitre_tactic ||
                                'Not mapped'}
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">
                              Technique
                            </dt>

                            <dd className="mt-1 font-semibold">
                              {
                                finding.mitre_technique_id
                              }
                              {finding.mitre_technique_name
                                ? ` — ${finding.mitre_technique_name}`
                                : ''}
                            </dd>
                          </div>
                        </dl>
                      </div>

                      <div className="rounded-2xl border border-cyan/20 bg-cyan/5 p-5">
                        <div className="flex items-center gap-2 text-cyan">
                          <Gauge
                            size={19}
                          />

                          <h4 className="font-semibold">
                            Evidence linkage
                          </h4>
                        </div>

                        <dl className="mt-4 space-y-4 text-sm">
                          <div>
                            <dt className="text-slate-500">
                              Evidence ID
                            </dt>

                            <dd className="mt-1 break-all text-xs text-slate-300">
                              {
                                finding.evidence_id
                              }
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">
                              Parsed event ID
                            </dt>

                            <dd className="mt-1 break-all text-xs text-slate-300">
                              {
                                finding.parsed_event_id
                              }
                            </dd>
                          </div>

                          <div>
                            <dt className="text-slate-500">
                              Ingestion job ID
                            </dt>

                            <dd className="mt-1 break-all text-xs text-slate-300">
                              {
                                finding.ingestion_job_id
                              }
                            </dd>
                          </div>
                        </dl>
                      </div>
                    </div>

                    <div className="mt-5 rounded-2xl border border-white/10 bg-slate-950/30 p-5">
                      <h4 className="font-semibold">
                        Detection indicators
                      </h4>

                      {indicators.length ===
                      0 ? (
                        <p className="mt-3 text-sm text-slate-500">
                          No indicators were
                          recorded.
                        </p>
                      ) : (
                        <dl className="mt-4 grid gap-4 md:grid-cols-2">
                          {indicators.map(
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

                    <p className="mt-5 text-xs text-slate-500">
                      Finding created:{' '}
                      {formatDate(
                        finding.created_at,
                      )}
                    </p>
                  </article>
                )
              },
            )}
          </div>
        )}

      {!findingsQuery.isPending &&
        !findingsQuery.isError &&
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
                  findingsQuery.isFetching
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
                  findingsQuery.isFetching
                }
                onClick={() => {
                  setPage(
                    Math.min(
                      totalPages,
                      currentPage + 1,
                    ),
                  )
                }}
                className="flex items-center gap-2 rounded-xl border border-red-400/30 bg-red-400/10 px-4 py-2 text-sm font-semibold text-red-200 transition hover:bg-red-400/20 disabled:cursor-not-allowed disabled:opacity-40"
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