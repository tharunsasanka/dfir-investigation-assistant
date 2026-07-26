import { useQuery } from '@tanstack/react-query'
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
  FileCheck2,
  FileSearch,
  GitMerge,
  History,
  LoaderCircle,
  RefreshCw,
  Search,
  ShieldAlert,
  UserRound,
  XCircle,
} from 'lucide-react'
import { useState } from 'react'
import type {
  FormEvent,
  ReactNode,
} from 'react'

import {
  listCaseForensicTimeline,
} from '../../api/forensicTimeline'
import type {
  ForensicTimelineEntry,
  ForensicTimelineEntryType,
  ForensicTimelineJsonValue,
  ForensicTimelineSeverity,
  ForensicTimelineSortOrder,
} from '../../types/forensicTimeline'

type CaseForensicTimelineProps = {
  caseId: string
}

const entryTypeOptions: Array<{
  label: string
  value: ForensicTimelineEntryType | ''
}> = [
  {
    label: 'All timeline entries',
    value: '',
  },
  {
    label: 'Parsed log events',
    value: 'log_event',
  },
  {
    label: 'Security findings',
    value: 'security_finding',
  },
  {
    label: 'Event correlations',
    value: 'event_correlation',
  },
  {
    label: 'Case audit activity',
    value: 'case_audit',
  },
  {
    label: 'Evidence custody',
    value: 'evidence_custody',
  },
]

const severityOptions: Array<{
  label: string
  value: ForensicTimelineSeverity | ''
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

function toIsoDate(
  value: string,
): string | undefined {
  if (!value) {
    return undefined
  }

  const parsedDate = new Date(value)

  if (
    Number.isNaN(
      parsedDate.getTime(),
    )
  ) {
    return undefined
  }

  return parsedDate.toISOString()
}

function formatJsonValue(
  value: ForensicTimelineJsonValue,
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
    'The unified forensic timeline could ' +
    'not be loaded from the server.'
  )
}

function getSeverityClasses(
  severity: ForensicTimelineSeverity,
): string {
  const classes: Record<
    ForensicTimelineSeverity,
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

function getEntryTypeClasses(
  entryType: ForensicTimelineEntryType,
): string {
  const classes: Record<
    ForensicTimelineEntryType,
    string
  > = {
    log_event:
      'border-cyan/30 bg-cyan/10 text-cyan',
    security_finding:
      'border-red-400/30 bg-red-400/10 text-red-200',
    event_correlation:
      'border-violet-400/30 bg-violet-400/10 text-violet-200',
    case_audit:
      'border-amber-400/30 bg-amber-400/10 text-amber-200',
    evidence_custody:
      'border-emerald-400/30 bg-emerald-400/10 text-emerald-200',
  }

  return classes[entryType]
}

function getEntryIcon(
  entryType: ForensicTimelineEntryType,
): ReactNode {
  if (
    entryType === 'log_event'
  ) {
    return <Database size={20} />
  }

  if (
    entryType === 'security_finding'
  ) {
    return <ShieldAlert size={20} />
  }

  if (
    entryType === 'event_correlation'
  ) {
    return <GitMerge size={20} />
  }

  if (
    entryType === 'case_audit'
  ) {
    return <History size={20} />
  }

  return <FileCheck2 size={20} />
}

function getEntryIconClasses(
  entryType: ForensicTimelineEntryType,
): string {
  const classes: Record<
    ForensicTimelineEntryType,
    string
  > = {
    log_event:
      'bg-cyan/10 text-cyan',
    security_finding:
      'bg-red-400/10 text-red-300',
    event_correlation:
      'bg-violet-400/10 text-violet-300',
    case_audit:
      'bg-amber-400/10 text-amber-300',
    evidence_custody:
      'bg-emerald-400/10 text-emerald-300',
  }

  return classes[entryType]
}

function TimelineMetadata({
  entry,
}: {
  entry: ForensicTimelineEntry
}) {
  const values = [
    {
      label: 'Event code',
      value: entry.event_code,
    },
    {
      label: 'Rule ID',
      value: entry.rule_id,
    },
    {
      label: 'Host',
      value: entry.host,
    },
    {
      label: 'Username',
      value: entry.username,
    },
    {
      label: 'Process',
      value: entry.process_name,
    },
    {
      label: 'Source IP',
      value: entry.source_ip,
    },
    {
      label: 'Destination IP',
      value: entry.destination_ip,
    },
    {
      label: 'Actor',
      value:
        entry.actor_full_name ||
        entry.actor_email,
    },
    {
      label: 'MITRE tactic',
      value: entry.mitre_tactic,
    },
    {
      label: 'MITRE technique',
      value:
        entry.mitre_technique_id
          ? [
              entry.mitre_technique_id,
              entry.mitre_technique_name,
            ]
              .filter(Boolean)
              .join(' — ')
          : '',
    },
    {
      label: 'Correlation type',
      value: entry.correlation_type
        ? formatLabel(
            entry.correlation_type,
          )
        : '',
    },
    {
      label: 'Correlation key',
      value: entry.correlation_key,
    },
  ].filter(
    (item) =>
      Boolean(item.value),
  )

  if (values.length === 0) {
    return null
  }

  return (
    <dl className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {values.map((item) => (
        <div
          key={item.label}
          className="rounded-xl border border-white/10 bg-slate-950/30 p-4"
        >
          <dt className="text-xs uppercase tracking-wider text-slate-500">
            {item.label}
          </dt>

          <dd className="mt-2 break-words text-sm font-semibold text-slate-200">
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function CaseForensicTimeline({
  caseId,
}: CaseForensicTimelineProps) {
  const [page, setPage] =
    useState(1)

  const [pageSize, setPageSize] =
    useState(20)

  const [
    searchInput,
    setSearchInput,
  ] = useState('')

  const [
    appliedSearch,
    setAppliedSearch,
  ] = useState('')

  const [
    selectedEntryType,
    setSelectedEntryType,
  ] = useState<
    ForensicTimelineEntryType | ''
  >('')

  const [
    selectedSeverity,
    setSelectedSeverity,
  ] = useState<
    ForensicTimelineSeverity | ''
  >('')

  const [
    sortOrder,
    setSortOrder,
  ] = useState<
    ForensicTimelineSortOrder
  >('descending')

  const [
    startTime,
    setStartTime,
  ] = useState('')

  const [
    endTime,
    setEndTime,
  ] = useState('')

  const [
    expandedEntryId,
    setExpandedEntryId,
  ] = useState<string | null>(
    null,
  )

  const dateRangeInvalid = Boolean(
    startTime &&
      endTime &&
      startTime > endTime,
  )

  const timelineQuery = useQuery({
    queryKey: [
      'forensic-timeline',
      'case',
      caseId,
      page,
      pageSize,
      appliedSearch,
      selectedEntryType,
      selectedSeverity,
      startTime,
      endTime,
      sortOrder,
    ],

    queryFn: () =>
      listCaseForensicTimeline(
        caseId,
        {
          page,
          page_size: pageSize,
          search:
            appliedSearch ||
            undefined,
          entry_type:
            selectedEntryType
              ? [selectedEntryType]
              : undefined,
          severity:
            selectedSeverity ||
            undefined,
          start_time:
            toIsoDate(startTime),
          end_time:
            toIsoDate(endTime),
          sort_order: sortOrder,
        },
      ),

    enabled:
      Boolean(caseId) &&
      !dateRangeInvalid,
  })

  const response =
    timelineQuery.data

  const timelineEntries =
    response?.items ?? []

  const summary =
    response?.summary

  const currentPage =
    response?.page ?? page

  const totalPages =
    response?.pages ?? 0

  const totalEntries =
    response?.total ?? 0

  function handleSearchSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    if (dateRangeInvalid) {
      return
    }

    setAppliedSearch(
      searchInput.trim(),
    )

    setPage(1)
  }

  function clearFilters() {
    setSearchInput('')
    setAppliedSearch('')
    setSelectedEntryType('')
    setSelectedSeverity('')
    setStartTime('')
    setEndTime('')
    setSortOrder('descending')
    setPage(1)
  }

  function toggleEntry(
    entryId: string,
  ) {
    setExpandedEntryId(
      (currentEntryId) =>
        currentEntryId === entryId
          ? null
          : entryId,
    )
  }

  const hasActiveFilters = Boolean(
    appliedSearch ||
      selectedEntryType ||
      selectedSeverity ||
      startTime ||
      endTime ||
      sortOrder !== 'descending',
  )

  return (
    <section className="glass rounded-3xl p-6 sm:p-8">
      <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
        <div className="flex items-start gap-3">
          <div className="rounded-2xl bg-cyan/10 p-3 text-cyan">
            <Clock3 size={25} />
          </div>

          <div>
            <p className="text-sm text-cyan">
              Chronological investigation view
            </p>

            <h2 className="mt-1 text-2xl font-bold">
              Unified Forensic Timeline
            </h2>

            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Review parsed events, automated
              findings, cross-evidence
              correlations, case changes, and
              evidence custody activity in one
              chronological investigation view.
            </p>
          </div>
        </div>

        <button
          type="button"
          disabled={
            timelineQuery.isFetching ||
            dateRangeInvalid
          }
          onClick={() => {
            void timelineQuery.refetch()
          }}
          className="flex items-center justify-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm font-semibold text-cyan transition hover:bg-cyan/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw
            size={17}
            className={
              timelineQuery.isFetching
                ? 'animate-spin'
                : ''
            }
          />

          Refresh
        </button>
      </div>

      {summary && (
        <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
          <article className="rounded-2xl border border-white/10 bg-white/5 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">
              Total entries
            </p>

            <p className="mt-2 text-2xl font-bold">
              {summary.total_entries.toLocaleString()}
            </p>
          </article>

          <article className="rounded-2xl border border-cyan/20 bg-cyan/5 p-4">
            <p className="text-xs uppercase tracking-wider text-cyan/70">
              Log events
            </p>

            <p className="mt-2 text-2xl font-bold text-cyan">
              {summary.log_event_count.toLocaleString()}
            </p>
          </article>

          <article className="rounded-2xl border border-red-400/20 bg-red-400/5 p-4">
            <p className="text-xs uppercase tracking-wider text-red-300/70">
              Findings
            </p>

            <p className="mt-2 text-2xl font-bold text-red-200">
              {summary.security_finding_count.toLocaleString()}
            </p>
          </article>

          <article className="rounded-2xl border border-violet-400/20 bg-violet-400/5 p-4">
            <p className="text-xs uppercase tracking-wider text-violet-300/70">
              Correlations
            </p>

            <p className="mt-2 text-2xl font-bold text-violet-200">
              {summary.event_correlation_count.toLocaleString()}
            </p>
          </article>

          <article className="rounded-2xl border border-amber-400/20 bg-amber-400/5 p-4">
            <p className="text-xs uppercase tracking-wider text-amber-300/70">
              Case audits
            </p>

            <p className="mt-2 text-2xl font-bold text-amber-200">
              {summary.case_audit_count.toLocaleString()}
            </p>
          </article>

          <article className="rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-4">
            <p className="text-xs uppercase tracking-wider text-emerald-300/70">
              Custody events
            </p>

            <p className="mt-2 text-2xl font-bold text-emerald-200">
              {summary.evidence_custody_count.toLocaleString()}
            </p>
          </article>
        </div>
      )}

      {summary && (
        <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <article className="rounded-2xl border border-red-400/20 bg-red-400/5 p-4">
            <p className="text-xs uppercase tracking-wider text-red-300/70">
              Critical entries
            </p>

            <p className="mt-2 text-xl font-bold text-red-200">
              {summary.critical_count.toLocaleString()}
            </p>
          </article>

          <article className="rounded-2xl border border-orange-400/20 bg-orange-400/5 p-4">
            <p className="text-xs uppercase tracking-wider text-orange-300/70">
              High entries
            </p>

            <p className="mt-2 text-xl font-bold text-orange-200">
              {summary.high_count.toLocaleString()}
            </p>
          </article>

          <article className="rounded-2xl border border-white/10 bg-white/5 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">
              First activity
            </p>

            <p className="mt-2 text-sm font-semibold">
              {formatDate(
                summary.first_event_at,
              )}
            </p>
          </article>

          <article className="rounded-2xl border border-white/10 bg-white/5 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">
              Last activity
            </p>

            <p className="mt-2 text-sm font-semibold">
              {formatDate(
                summary.last_event_at,
              )}
            </p>
          </article>
        </div>
      )}

      <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5">
        <form
          onSubmit={
            handleSearchSubmit
          }
          className="grid gap-4 xl:grid-cols-4"
        >
          <label className="text-sm xl:col-span-2">
            Search timeline

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
                placeholder="Event code, rule, host, user, IP, MITRE..."
                className="w-full rounded-xl border border-white/10 bg-slate-900 py-3 pl-11 pr-4 outline-none transition focus:border-cyan/60"
              />
            </div>
          </label>

          <label className="text-sm">
            Entry type

            <select
              value={
                selectedEntryType
              }
              onChange={(event) => {
                setSelectedEntryType(
                  event.target.value as ForensicTimelineEntryType | '',
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            >
              {entryTypeOptions.map(
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
            Severity

            <select
              value={
                selectedSeverity
              }
              onChange={(event) => {
                setSelectedSeverity(
                  event.target.value as ForensicTimelineSeverity | '',
                )

                setPage(1)
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
            Start time

            <input
              type="datetime-local"
              value={startTime}
              onChange={(event) => {
                setStartTime(
                  event.target.value,
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            />
          </label>

          <label className="text-sm">
            End time

            <input
              type="datetime-local"
              value={endTime}
              onChange={(event) => {
                setEndTime(
                  event.target.value,
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            />
          </label>

          <label className="text-sm">
            Sort order

            <select
              value={sortOrder}
              onChange={(event) => {
                setSortOrder(
                  event.target.value as ForensicTimelineSortOrder,
                )

                setPage(1)
              }}
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            >
              <option value="descending">
                Newest first
              </option>

              <option value="ascending">
                Oldest first
              </option>
            </select>
          </label>

          <div className="flex items-end gap-3">
            <button
              type="submit"
              disabled={dateRangeInvalid}
              className="flex min-h-12 items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Search size={17} />
              Apply
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

        {dateRangeInvalid && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-red-200"
          >
            <AlertTriangle
              size={19}
              className="mt-0.5 shrink-0"
            />

            <p className="text-sm">
              The start time cannot be later
              than the end time.
            </p>
          </div>
        )}
      </div>

      <div className="mt-6 flex flex-col gap-4 border-b border-white/10 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="font-semibold">
            {totalEntries.toLocaleString()}
            {' '}
            timeline entr
            {totalEntries === 1
              ? 'y'
              : 'ies'}
          </p>

          <p className="mt-1 text-sm text-slate-500">
            Page {currentPage}
            {totalPages > 0
              ? ` of ${totalPages}`
              : ''}
          </p>
        </div>

        <label className="text-sm text-slate-400">
          Entries per page

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
            <option value={10}>
              10
            </option>

            <option value={20}>
              20
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

      {timelineQuery.isPending &&
        !dateRangeInvalid && (
          <div className="grid min-h-72 place-items-center">
            <div className="text-center">
              <LoaderCircle
                size={32}
                className="mx-auto animate-spin text-cyan"
              />

              <p className="mt-3 text-sm text-slate-400">
                Building forensic timeline...
              </p>
            </div>
          </div>
        )}

      {timelineQuery.isError && (
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
              Timeline unavailable
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              {getErrorMessage(
                timelineQuery.error,
              )}
            </p>
          </div>
        </div>
      )}

      {!timelineQuery.isPending &&
        !timelineQuery.isError &&
        !dateRangeInvalid &&
        timelineEntries.length === 0 && (
          <div className="grid min-h-72 place-items-center">
            <div className="max-w-md text-center">
              <Clock3
                size={40}
                className="mx-auto text-slate-600"
              />

              <p className="mt-4 font-semibold">
                No timeline entries found
              </p>

              <p className="mt-2 text-sm leading-6 text-slate-500">
                No forensic activity matches
                the current filters. Upload and
                ingest evidence to populate the
                investigation timeline.
              </p>
            </div>
          </div>
        )}

      {!timelineQuery.isPending &&
        !timelineQuery.isError &&
        timelineEntries.length > 0 && (
          <div className="relative mt-6 space-y-5 before:absolute before:bottom-5 before:left-[23px] before:top-5 before:w-px before:bg-white/10">
            {timelineEntries.map(
              (entry) => {
                const details =
                  Object.entries(
                    entry.details,
                  )

                const isExpanded =
                  expandedEntryId ===
                  entry.id

                return (
                  <article
                    key={entry.id}
                    className="relative pl-14"
                  >
                    <div
                      className={[
                        'absolute left-0 top-5 z-10 grid h-12 w-12 place-items-center rounded-2xl border border-white/10',
                        getEntryIconClasses(
                          entry.entry_type,
                        ),
                      ].join(' ')}
                    >
                      {getEntryIcon(
                        entry.entry_type,
                      )}
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-white/5 p-5 sm:p-6">
                      <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="break-words text-lg font-semibold">
                              {entry.title}
                            </h3>

                            <span
                              className={[
                                'rounded-full border px-3 py-1 text-xs font-semibold',
                                getEntryTypeClasses(
                                  entry.entry_type,
                                ),
                              ].join(' ')}
                            >
                              {formatLabel(
                                entry.entry_type,
                              )}
                            </span>

                            <span
                              className={[
                                'rounded-full border px-3 py-1 text-xs font-semibold',
                                getSeverityClasses(
                                  entry.severity,
                                ),
                              ].join(' ')}
                            >
                              {formatLabel(
                                entry.severity,
                              )}
                            </span>

                            {entry.confidence !==
                              null && (
                              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs font-semibold text-slate-300">
                                {entry.confidence}
                                % confidence
                              </span>
                            )}
                          </div>

                          <p className="mt-3 text-sm leading-6 text-slate-300">
                            {entry.description}
                          </p>

                          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-xs text-slate-500">
                            <span>
                              Source:{' '}
                              {formatLabel(
                                entry.source_type,
                              )}
                            </span>

                            <span className="break-all">
                              Source ID:{' '}
                              {entry.source_id}
                            </span>
                          </div>
                        </div>

                        <div className="shrink-0 xl:text-right">
                          <p className="text-xs uppercase tracking-wider text-slate-500">
                            Occurred
                          </p>

                          <p className="mt-1 text-sm font-semibold text-slate-200">
                            {formatDate(
                              entry.occurred_at,
                            )}
                          </p>
                        </div>
                      </div>

                      <TimelineMetadata
                        entry={entry}
                      />

                      <div className="mt-5 flex flex-col gap-3 border-t border-white/10 pt-4 sm:flex-row sm:items-center sm:justify-between">
                        <div className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-slate-500">
                          <span>
                            Recorded:{' '}
                            {formatDate(
                              entry.recorded_at,
                            )}
                          </span>

                          {entry.evidence_id && (
                            <span className="break-all">
                              Evidence ID:{' '}
                              {entry.evidence_id}
                            </span>
                          )}
                        </div>

                        <button
                          type="button"
                          onClick={() => {
                            toggleEntry(
                              entry.id,
                            )
                          }}
                          className="flex items-center justify-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-cyan/30 hover:text-cyan"
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

                      {isExpanded && (
                        <div className="mt-5 rounded-2xl border border-white/10 bg-slate-950/30 p-5">
                          <div className="flex items-center gap-2">
                            <FileSearch
                              size={19}
                              className="text-cyan"
                            />

                            <h4 className="font-semibold">
                              Timeline metadata
                            </h4>
                          </div>

                          {details.length ===
                          0 ? (
                            <p className="mt-3 text-sm text-slate-500">
                              No additional
                              metadata was
                              recorded.
                            </p>
                          ) : (
                            <dl className="mt-4 grid gap-4 md:grid-cols-2">
                              {details.map(
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

                                    <dd className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words text-sm text-slate-200">
                                      {formatJsonValue(
                                        value,
                                      )}
                                    </dd>
                                  </div>
                                ),
                              )}
                            </dl>
                          )}

                          <div className="mt-5 grid gap-3 border-t border-white/10 pt-4 text-xs text-slate-500 md:grid-cols-2">
                            <p className="break-all">
                              Timeline ID:{' '}
                              {entry.id}
                            </p>

                            {entry.parsed_event_id && (
                              <p className="break-all">
                                Parsed event ID:{' '}
                                {
                                  entry.parsed_event_id
                                }
                              </p>
                            )}

                            {entry.security_finding_id && (
                              <p className="break-all">
                                Security finding ID:{' '}
                                {
                                  entry.security_finding_id
                                }
                              </p>
                            )}

                            {entry.correlation_id && (
                              <p className="break-all">
                                Correlation ID:{' '}
                                {
                                  entry.correlation_id
                                }
                              </p>
                            )}

                            {entry.custody_event_id && (
                              <p className="break-all">
                                Custody event ID:{' '}
                                {
                                  entry.custody_event_id
                                }
                              </p>
                            )}

                            {entry.audit_event_id && (
                              <p className="break-all">
                                Audit event ID:{' '}
                                {
                                  entry.audit_event_id
                                }
                              </p>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </article>
                )
              },
            )}
          </div>
        )}

      {!timelineQuery.isPending &&
        !timelineQuery.isError &&
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
                  timelineQuery.isFetching
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
                  timelineQuery.isFetching
                }
                onClick={() => {
                  setPage(
                    Math.min(
                      totalPages,
                      currentPage + 1,
                    ),
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