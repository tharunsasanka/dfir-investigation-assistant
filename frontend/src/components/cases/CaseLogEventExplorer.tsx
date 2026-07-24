import { useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  AlertTriangle,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  CircleAlert,
  Database,
  FileSearch,
  Filter,
  LoaderCircle,
  RefreshCw,
  Search,
  Server,
  TerminalSquare,
  User,
} from 'lucide-react'
import {
  useState,
  type FormEvent,
} from 'react'

import {
  listCaseLogEvents,
} from '../../api/logEvents'
import type {
  LogEventSeverity,
  ParsedLogEvent,
} from '../../types/logEvents'

type EvidenceOption = {
  id: string
  original_filename: string
}

type CaseLogEventExplorerProps = {
  caseId: string
  evidenceOptions?: EvidenceOption[]
}

const severityOptions: Array<{
  value: LogEventSeverity | ''
  label: string
}> = [
  {
    value: '',
    label: 'All severities',
  },
  {
    value: 'unknown',
    label: 'Unknown',
  },
  {
    value: 'informational',
    label: 'Informational',
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

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'No timestamp'
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

function severityClassName(
  severity: LogEventSeverity,
): string {
  const classNames: Record<
    LogEventSeverity,
    string
  > = {
    unknown:
      'border-slate-400/20 bg-slate-400/10 text-slate-300',

    informational:
      'border-cyan/20 bg-cyan/10 text-cyan',

    low:
      'border-emerald-400/20 bg-emerald-400/10 text-emerald-300',

    medium:
      'border-amber-400/20 bg-amber-400/10 text-amber-200',

    high:
      'border-orange-400/20 bg-orange-400/10 text-orange-200',

    critical:
      'border-red-400/30 bg-red-400/10 text-red-200',
  }

  return classNames[severity]
}

function getErrorMessage(
  error: unknown,
): string {
  if (
    isAxiosError(error) &&
    typeof error.response?.data?.detail
      === 'string'
  ) {
    return error.response.data.detail
  }

  return (
    'Parsed log events could not be ' +
    'loaded from the server.'
  )
}

function stringifyJson(
  value: Record<string, unknown>,
): string {
  try {
    return JSON.stringify(
      value,
      null,
      2,
    )
  } catch {
    return 'Unable to display this event data.'
  }
}

function EventMetadata({
  event,
}: {
  event: ParsedLogEvent
}) {
  const metadata = [
    {
      label: 'Host',
      value: event.host,
      icon: Server,
    },
    {
      label: 'Username',
      value: event.username,
      icon: User,
    },
    {
      label: 'Process',
      value: event.process_name,
      icon: TerminalSquare,
    },
    {
      label: 'Event code',
      value: event.event_code,
      icon: Database,
    },
    {
      label: 'Source IP',
      value: event.source_ip,
      icon: ChevronRight,
    },
    {
      label: 'Destination IP',
      value: event.destination_ip,
      icon: ChevronLeft,
    },
  ].filter(
    (item) =>
      item.value.trim().length > 0,
  )

  if (metadata.length === 0) {
    return (
      <p className="mt-4 text-sm text-slate-500">
        No additional normalized metadata was
        extracted from this record.
      </p>
    )
  }

  return (
    <dl className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {metadata.map((item) => {
        const Icon = item.icon

        return (
          <div
            key={item.label}
            className="rounded-xl border border-white/10 bg-slate-950/30 p-3"
          >
            <dt className="flex items-center gap-2 text-xs uppercase tracking-wider text-slate-500">
              <Icon size={14} />
              {item.label}
            </dt>

            <dd className="mt-2 break-all text-sm text-slate-300">
              {item.value}
            </dd>
          </div>
        )
      })}
    </dl>
  )
}

export function CaseLogEventExplorer({
  caseId,
  evidenceOptions = [],
}: CaseLogEventExplorerProps) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] =
    useState(25)

  const [
    searchInput,
    setSearchInput,
  ] = useState('')

  const [
    severityInput,
    setSeverityInput,
  ] =
    useState<LogEventSeverity | ''>('')

  const [
    evidenceInput,
    setEvidenceInput,
  ] = useState('')

  const [
    appliedSearch,
    setAppliedSearch,
  ] = useState('')

  const [
    appliedSeverity,
    setAppliedSeverity,
  ] =
    useState<LogEventSeverity | ''>('')

  const [
    appliedEvidenceId,
    setAppliedEvidenceId,
  ] = useState('')

  const [
    expandedEventId,
    setExpandedEventId,
  ] = useState<string | null>(null)

  const eventsQuery = useQuery({
    queryKey: [
      'log-events',
      'case',
      caseId,
      page,
      pageSize,
      appliedSearch,
      appliedSeverity,
      appliedEvidenceId,
    ],

    queryFn: () =>
      listCaseLogEvents(
        caseId,
        {
          page,
          page_size: pageSize,

          search:
            appliedSearch ||
            undefined,

          severity:
            appliedSeverity ||
            undefined,

          evidence_id:
            appliedEvidenceId ||
            undefined,
        },
      ),
  })

  function handleFilterSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    setAppliedSearch(
      searchInput.trim(),
    )

    setAppliedSeverity(
      severityInput,
    )

    setAppliedEvidenceId(
      evidenceInput,
    )

    setPage(1)
    setExpandedEventId(null)
  }

  function clearFilters() {
    setSearchInput('')
    setSeverityInput('')
    setEvidenceInput('')

    setAppliedSearch('')
    setAppliedSeverity('')
    setAppliedEvidenceId('')

    setPage(1)
    setExpandedEventId(null)
  }

  const response = eventsQuery.data
  const events = response?.items ?? []

  const currentPage =
    response?.page ?? page

  const totalPages =
    response?.pages ?? 0

  const totalRecords =
    response?.total ?? 0

  const hasFilters =
    appliedSearch.length > 0 ||
    appliedSeverity.length > 0 ||
    appliedEvidenceId.length > 0

  return (
    <section className="glass rounded-3xl p-6 sm:p-8">
      <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
        <div className="flex items-start gap-3">
          <div className="rounded-2xl bg-cyan/10 p-3 text-cyan">
            <FileSearch size={24} />
          </div>

          <div>
            <p className="text-sm text-cyan">
              Normalized forensic events
            </p>

            <h2 className="mt-1 text-2xl font-bold">
              Parsed Log Event Explorer
            </h2>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Search and review log records parsed
              from uploaded evidence without
              modifying the original evidence files.
            </p>
          </div>
        </div>

        <button
          type="button"
          disabled={
            eventsQuery.isFetching
          }
          onClick={() => {
            void eventsQuery.refetch()
          }}
          className="flex items-center justify-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm font-semibold text-cyan transition hover:bg-cyan/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw
            size={17}
            className={
              eventsQuery.isFetching
                ? 'animate-spin'
                : ''
            }
          />

          Refresh
        </button>
      </div>

      <form
        onSubmit={handleFilterSubmit}
        className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5"
      >
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Filter
            size={17}
            className="text-cyan"
          />

          Event filters
        </div>

        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          <label className="text-sm">
            Search

            <div className="relative mt-2">
              <Search
                size={17}
                className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
              />

              <input
                type="search"
                value={searchInput}
                onChange={(event) => {
                  setSearchInput(
                    event.target.value,
                  )
                }}
                placeholder="Message, host, user, process, IP..."
                className="w-full rounded-xl border border-white/10 bg-slate-900 py-3 pl-11 pr-4 outline-none transition focus:border-cyan/60"
              />
            </div>
          </label>

          <label className="text-sm">
            Severity

            <select
              value={severityInput}
              onChange={(event) => {
                setSeverityInput(
                  event.target.value as (LogEventSeverity | ''),
                )
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            >
              {severityOptions.map(
                (option) => (
                  <option
                    key={
                      option.value ||
                      'all'
                    }
                    value={option.value}
                  >
                    {option.label}
                  </option>
                ),
              )}
            </select>
          </label>

          <label className="text-sm">
            Evidence source

            {evidenceOptions.length > 0 ? (
              <select
                value={evidenceInput}
                onChange={(event) => {
                  setEvidenceInput(
                    event.target.value,
                  )
                }}
                className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
              >
                <option value="">
                  All evidence
                </option>

                {evidenceOptions.map(
                  (evidence) => (
                    <option
                      key={evidence.id}
                      value={evidence.id}
                    >
                      {
                        evidence
                          .original_filename
                      }
                    </option>
                  ),
                )}
              </select>
            ) : (
              <input
                type="text"
                value={evidenceInput}
                onChange={(event) => {
                  setEvidenceInput(
                    event.target.value,
                  )
                }}
                placeholder="Optional evidence UUID"
                className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
              />
            )}
          </label>
        </div>

        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={clearFilters}
            disabled={!hasFilters}
            className="rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-white/20 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            Clear filters
          </button>

          <button
            type="submit"
            className="flex items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-2 text-sm font-semibold text-slate-950 transition hover:brightness-110"
          >
            <Search size={17} />
            Apply filters
          </button>
        </div>
      </form>

      <div className="mt-6 flex flex-col gap-3 border-b border-white/10 pb-5 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="font-semibold">
            {totalRecords.toLocaleString()}
            {' '}
            event
            {totalRecords === 1
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

        <label className="flex items-center gap-3 text-sm text-slate-400">
          Events per page

          <select
            value={pageSize}
            onChange={(event) => {
              setPageSize(
                Number(
                  event.target.value,
                ),
              )

              setPage(1)
              setExpandedEventId(null)
            }}
            className="rounded-xl border border-white/10 bg-slate-900 px-3 py-2 text-white outline-none focus:border-cyan/60"
          >
            <option value={10}>
              10
            </option>

            <option value={25}>
              25
            </option>

            <option value={50}>
              50
            </option>

            <option value={100}>
              100
            </option>
          </select>
        </label>
      </div>

      {eventsQuery.isPending && (
        <div className="grid min-h-64 place-items-center">
          <div className="text-center">
            <LoaderCircle
              size={30}
              className="mx-auto animate-spin text-cyan"
            />

            <p className="mt-3 text-sm text-slate-400">
              Loading parsed log events...
            </p>
          </div>
        </div>
      )}

      {eventsQuery.isError && (
        <div
          role="alert"
          className="mt-6 flex items-start gap-3 rounded-2xl border border-red-400/30 bg-red-400/10 p-5 text-red-200"
        >
          <CircleAlert
            size={21}
            className="mt-0.5 shrink-0"
          />

          <div>
            <p className="font-semibold">
              Event explorer unavailable
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              {getErrorMessage(
                eventsQuery.error,
              )}
            </p>
          </div>
        </div>
      )}

      {!eventsQuery.isPending &&
        !eventsQuery.isError &&
        events.length === 0 && (
          <div className="grid min-h-64 place-items-center">
            <div className="max-w-md text-center">
              <Database
                size={34}
                className="mx-auto text-slate-600"
              />

              <p className="mt-4 font-semibold">
                No parsed events found
              </p>

              <p className="mt-2 text-sm leading-6 text-slate-500">
                Upload log evidence and run log
                ingestion, or adjust the current
                search filters.
              </p>
            </div>
          </div>
        )}

      {!eventsQuery.isPending &&
        !eventsQuery.isError &&
        events.length > 0 && (
          <div className="mt-5 space-y-4">
            {events.map((event) => {
              const isExpanded =
                expandedEventId ===
                event.id

              return (
                <article
                  key={event.id}
                  className="rounded-2xl border border-white/10 bg-white/5 p-5"
                >
                  <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={[
                            'rounded-full border px-3 py-1 text-xs font-semibold',
                            severityClassName(
                              event.severity,
                            ),
                          ].join(' ')}
                        >
                          {formatLabel(
                            event.severity,
                          )}
                        </span>

                        <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-400">
                          {formatLabel(
                            event.source_type,
                          )}
                        </span>

                        {event.parse_error && (
                          <span className="flex items-center gap-1 rounded-full border border-red-400/30 bg-red-400/10 px-3 py-1 text-xs font-semibold text-red-200">
                            <AlertTriangle
                              size={13}
                            />
                            Parse error
                          </span>
                        )}
                      </div>

                      <p className="mt-3 text-sm text-slate-500">
                        {formatDate(
                          event.event_time,
                        )}
                      </p>

                      <p className="mt-3 whitespace-pre-wrap break-words leading-7 text-slate-200">
                        {event.message ||
                          'No message was extracted.'}
                      </p>
                    </div>

                    <button
                      type="button"
                      onClick={() => {
                        setExpandedEventId(
                          isExpanded
                            ? null
                            : event.id,
                        )
                      }}
                      aria-expanded={
                        isExpanded
                      }
                      className="flex shrink-0 items-center justify-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-cyan/30 hover:text-cyan"
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
                        ? 'Hide details'
                        : 'View details'}
                    </button>
                  </div>

                  <EventMetadata
                    event={event}
                  />

                  {isExpanded && (
                    <div className="mt-5 space-y-5 border-t border-white/10 pt-5">
                      <dl className="grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-4">
                        <div>
                          <dt className="text-xs uppercase tracking-wider text-slate-500">
                            Event index
                          </dt>

                          <dd className="mt-1 text-slate-300">
                            {
                              event.event_index
                            }
                          </dd>
                        </div>

                        <div>
                          <dt className="text-xs uppercase tracking-wider text-slate-500">
                            Evidence ID
                          </dt>

                          <dd className="mt-1 break-all text-xs text-slate-400">
                            {
                              event.evidence_id
                            }
                          </dd>
                        </div>

                        <div>
                          <dt className="text-xs uppercase tracking-wider text-slate-500">
                            Ingestion job
                          </dt>

                          <dd className="mt-1 break-all text-xs text-slate-400">
                            {
                              event
                                .ingestion_job_id
                            }
                          </dd>
                        </div>

                        <div>
                          <dt className="text-xs uppercase tracking-wider text-slate-500">
                            Database record
                          </dt>

                          <dd className="mt-1 break-all text-xs text-slate-400">
                            {event.id}
                          </dd>
                        </div>
                      </dl>

                      {event.parse_error && (
                        <div className="rounded-xl border border-red-400/30 bg-red-400/10 p-4">
                          <p className="text-xs uppercase tracking-wider text-red-300/70">
                            Parse error
                          </p>

                          <p className="mt-2 whitespace-pre-wrap break-words text-sm text-red-200">
                            {
                              event.parse_error
                            }
                          </p>
                        </div>
                      )}

                      <div className="grid gap-5 xl:grid-cols-2">
                        <div>
                          <p className="text-sm font-semibold">
                            Normalized event
                          </p>

                          <pre className="mt-3 max-h-96 overflow-auto rounded-xl border border-white/10 bg-slate-950/70 p-4 text-xs leading-6 text-cyan">
                            {stringifyJson(
                              event
                                .normalized_event,
                            )}
                          </pre>
                        </div>

                        <div>
                          <p className="text-sm font-semibold">
                            Raw event
                          </p>

                          <pre className="mt-3 max-h-96 overflow-auto rounded-xl border border-white/10 bg-slate-950/70 p-4 text-xs leading-6 text-slate-300">
                            {stringifyJson(
                              event.raw_event,
                            )}
                          </pre>
                        </div>
                      </div>
                    </div>
                  )}
                </article>
              )
            })}
          </div>
        )}

      {!eventsQuery.isPending &&
        !eventsQuery.isError &&
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
                  eventsQuery.isFetching
                }
                onClick={() => {
                  setPage(
                    Math.max(
                      1,
                      currentPage - 1,
                    ),
                  )

                  setExpandedEventId(
                    null,
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
                  eventsQuery.isFetching
                }
                onClick={() => {
                  setPage(
                    Math.min(
                      totalPages,
                      currentPage + 1,
                    ),
                  )

                  setExpandedEventId(
                    null,
                  )
                }}
                className="flex items-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm font-semibold text-cyan transition hover:bg-cyan/20 disabled:cursor-not-allowed disabled:opacity-40"
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