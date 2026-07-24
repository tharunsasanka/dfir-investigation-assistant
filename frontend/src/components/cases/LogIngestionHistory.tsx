import { useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock3,
  Database,
  FileText,
  History,
  LoaderCircle,
  RefreshCw,
  UserRound,
  XCircle,
} from 'lucide-react'
import { useState } from 'react'

import {
  listCaseLogIngestionJobs,
} from '../../api/logIngestion'
import type {
  LogIngestionStatus,
} from '../../types/logIngestion'

type LogIngestionHistoryProps = {
  caseId: string
}

const statusOptions: Array<{
  value: LogIngestionStatus | ''
  label: string
}> = [
  {
    value: '',
    label: 'All statuses',
  },
  {
    value: 'pending',
    label: 'Pending',
  },
  {
    value: 'processing',
    label: 'Processing',
  },
  {
    value: 'completed',
    label: 'Completed',
  },
  {
    value: 'completed_with_errors',
    label: 'Completed with errors',
  },
  {
    value: 'failed',
    label: 'Failed',
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

function formatBytes(
  sizeBytes: number,
): string {
  if (sizeBytes < 1024) {
    return `${sizeBytes} B`
  }

  if (sizeBytes < 1024 * 1024) {
    return `${(
      sizeBytes / 1024
    ).toFixed(2)} KB`
  }

  if (
    sizeBytes <
    1024 * 1024 * 1024
  ) {
    return `${(
      sizeBytes /
      (1024 * 1024)
    ).toFixed(2)} MB`
  }

  return `${(
    sizeBytes /
    (1024 * 1024 * 1024)
  ).toFixed(2)} GB`
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
    'The log-ingestion history could not ' +
    'be loaded from the server.'
  )
}

function getStatusClasses(
  status: LogIngestionStatus,
): string {
  const classes: Record<
    LogIngestionStatus,
    string
  > = {
    pending:
      'border-slate-400/30 bg-slate-400/10 text-slate-300',

    processing:
      'border-cyan/30 bg-cyan/10 text-cyan',

    completed:
      'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',

    completed_with_errors:
      'border-amber-400/30 bg-amber-400/10 text-amber-200',

    failed:
      'border-red-400/30 bg-red-400/10 text-red-200',
  }

  return classes[status]
}

function StatusIcon({
  status,
}: {
  status: LogIngestionStatus
}) {
  if (status === 'completed') {
    return (
      <CheckCircle2
        size={18}
        className="text-emerald-300"
      />
    )
  }

  if (
    status ===
    'completed_with_errors'
  ) {
    return (
      <AlertTriangle
        size={18}
        className="text-amber-300"
      />
    )
  }

  if (status === 'failed') {
    return (
      <XCircle
        size={18}
        className="text-red-300"
      />
    )
  }

  if (status === 'processing') {
    return (
      <LoaderCircle
        size={18}
        className="animate-spin text-cyan"
      />
    )
  }

  return (
    <Clock3
      size={18}
      className="text-slate-400"
    />
  )
}

export function LogIngestionHistory({
  caseId,
}: LogIngestionHistoryProps) {
  const [page, setPage] = useState(1)

  const [pageSize, setPageSize] =
    useState(10)

  const [
    selectedStatus,
    setSelectedStatus,
  ] =
    useState<LogIngestionStatus | ''>('')

  const jobsQuery = useQuery({
    queryKey: [
      'log-ingestion-jobs',
      'case',
      caseId,
      page,
      pageSize,
      selectedStatus,
    ],

    queryFn: () =>
      listCaseLogIngestionJobs(
        caseId,
        {
          page,
          page_size: pageSize,
          status:
            selectedStatus ||
            undefined,
        },
      ),
  })

  const response = jobsQuery.data
  const jobs = response?.items ?? []

  const currentPage =
    response?.page ?? page

  const totalPages =
    response?.pages ?? 0

  const totalJobs =
    response?.total ?? 0

  return (
    <section className="glass rounded-3xl p-6 sm:p-8">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex items-start gap-3">
          <div className="rounded-2xl bg-violet-400/10 p-3 text-violet-300">
            <History size={24} />
          </div>

          <div>
            <p className="text-sm text-violet-300">
              Parser execution records
            </p>

            <h2 className="mt-1 text-2xl font-bold">
              Log Ingestion History
            </h2>

            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Review every log-processing job,
              including parser details, record
              counts, evidence source, requester,
              timestamps, and failures.
            </p>
          </div>
        </div>

        <button
          type="button"
          disabled={jobsQuery.isFetching}
          onClick={() => {
            void jobsQuery.refetch()
          }}
          className="flex items-center justify-center gap-2 rounded-xl border border-violet-400/30 bg-violet-400/10 px-4 py-2 text-sm font-semibold text-violet-200 transition hover:bg-violet-400/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw
            size={17}
            className={
              jobsQuery.isFetching
                ? 'animate-spin'
                : ''
            }
          />

          Refresh
        </button>
      </div>

      <div className="mt-6 flex flex-col gap-4 rounded-2xl border border-white/10 bg-white/5 p-5 md:flex-row md:items-end md:justify-between">
        <label className="w-full text-sm md:max-w-xs">
          Job status

          <select
            value={selectedStatus}
            onChange={(event) => {
              setSelectedStatus(
                event.target.value as LogIngestionStatus | '',
              )

              setPage(1)
            }}
            className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-violet-400/60"
          >
            {statusOptions.map(
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

        <label className="text-sm text-slate-400">
          Jobs per page

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
            className="mt-2 block rounded-xl border border-white/10 bg-slate-900 px-4 py-3 text-white outline-none transition focus:border-violet-400/60"
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

      <div className="mt-6 border-b border-white/10 pb-5">
        <p className="font-semibold">
          {totalJobs.toLocaleString()}
          {' '}
          ingestion job
          {totalJobs === 1
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

      {jobsQuery.isPending && (
        <div className="grid min-h-64 place-items-center">
          <div className="text-center">
            <LoaderCircle
              size={30}
              className="mx-auto animate-spin text-violet-300"
            />

            <p className="mt-3 text-sm text-slate-400">
              Loading ingestion history...
            </p>
          </div>
        </div>
      )}

      {jobsQuery.isError && (
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
              Ingestion history unavailable
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              {getErrorMessage(
                jobsQuery.error,
              )}
            </p>
          </div>
        </div>
      )}

      {!jobsQuery.isPending &&
        !jobsQuery.isError &&
        jobs.length === 0 && (
          <div className="grid min-h-64 place-items-center">
            <div className="max-w-md text-center">
              <Database
                size={34}
                className="mx-auto text-slate-600"
              />

              <p className="mt-4 font-semibold">
                No ingestion jobs found
              </p>

              <p className="mt-2 text-sm leading-6 text-slate-500">
                Upload log evidence and use the
                Ingest Logs action to create the
                first parser job.
              </p>
            </div>
          </div>
        )}

      {!jobsQuery.isPending &&
        !jobsQuery.isError &&
        jobs.length > 0 && (
          <div className="mt-5 space-y-4">
            {jobs.map((job) => (
              <article
                key={job.id}
                className="rounded-2xl border border-white/10 bg-white/5 p-5"
              >
                <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                  <div className="flex min-w-0 items-start gap-3">
                    <div className="rounded-xl bg-slate-950/40 p-3">
                      <StatusIcon
                        status={job.status}
                      />
                    </div>

                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="break-words font-semibold">
                          {
                            job.evidence_filename
                          }
                        </h3>

                        <span
                          className={[
                            'rounded-full border px-3 py-1 text-xs font-semibold',
                            getStatusClasses(
                              job.status,
                            ),
                          ].join(' ')}
                        >
                          {formatLabel(
                            job.status,
                          )}
                        </span>
                      </div>

                      <p className="mt-2 break-all text-xs text-slate-500">
                        Job ID: {job.id}
                      </p>
                    </div>
                  </div>

                  <div className="text-sm text-slate-400 xl:text-right">
                    <p>
                      Created
                    </p>

                    <p className="mt-1 font-medium text-slate-300">
                      {formatDate(
                        job.created_at,
                      )}
                    </p>
                  </div>
                </div>

                <dl className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                    <dt className="text-xs uppercase tracking-wider text-slate-500">
                      Requested format
                    </dt>

                    <dd className="mt-2 font-semibold">
                      {formatLabel(
                        job.requested_format,
                      )}
                    </dd>
                  </div>

                  <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                    <dt className="text-xs uppercase tracking-wider text-slate-500">
                      Detected format
                    </dt>

                    <dd className="mt-2 font-semibold">
                      {job.detected_format
                        ? formatLabel(
                            job.detected_format,
                          )
                        : 'Not detected'}
                    </dd>
                  </div>

                  <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                    <dt className="text-xs uppercase tracking-wider text-slate-500">
                      Parser
                    </dt>

                    <dd className="mt-2 break-words font-semibold">
                      {job.parser_name}
                      {' '}
                      v
                      {job.parser_version}
                    </dd>
                  </div>

                  <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                    <dt className="text-xs uppercase tracking-wider text-slate-500">
                      Processed size
                    </dt>

                    <dd className="mt-2 font-semibold">
                      {formatBytes(
                        job.processed_bytes,
                      )}
                    </dd>
                  </div>
                </dl>

                <dl className="mt-4 grid gap-4 sm:grid-cols-3">
                  <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                    <dt className="text-xs uppercase tracking-wider text-slate-500">
                      Total records
                    </dt>

                    <dd className="mt-2 text-xl font-bold">
                      {job.total_records}
                    </dd>
                  </div>

                  <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-4">
                    <dt className="text-xs uppercase tracking-wider text-emerald-300/70">
                      Parsed records
                    </dt>

                    <dd className="mt-2 text-xl font-bold text-emerald-300">
                      {job.parsed_records}
                    </dd>
                  </div>

                  <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4">
                    <dt className="text-xs uppercase tracking-wider text-red-300/70">
                      Failed records
                    </dt>

                    <dd className="mt-2 text-xl font-bold text-red-300">
                      {job.failed_records}
                    </dd>
                  </div>
                </dl>

                <dl className="mt-5 grid gap-4 text-sm md:grid-cols-2 xl:grid-cols-4">
                  <div>
                    <dt className="flex items-center gap-2 text-slate-500">
                      <FileText size={15} />
                      Evidence ID
                    </dt>

                    <dd className="mt-1 break-all text-xs text-slate-300">
                      {job.evidence_id}
                    </dd>
                  </div>

                  <div>
                    <dt className="flex items-center gap-2 text-slate-500">
                      <UserRound size={15} />
                      Requested by
                    </dt>

                    <dd className="mt-1 break-words text-slate-300">
                      {job.requested_by_email ||
                        'Unknown user'}
                    </dd>
                  </div>

                  <div>
                    <dt className="flex items-center gap-2 text-slate-500">
                      <Clock3 size={15} />
                      Started
                    </dt>

                    <dd className="mt-1 text-slate-300">
                      {formatDate(
                        job.started_at,
                      )}
                    </dd>
                  </div>

                  <div>
                    <dt className="flex items-center gap-2 text-slate-500">
                      <CheckCircle2
                        size={15}
                      />
                      Completed
                    </dt>

                    <dd className="mt-1 text-slate-300">
                      {formatDate(
                        job.completed_at,
                      )}
                    </dd>
                  </div>
                </dl>

                {job.error_message && (
                  <div className="mt-5 rounded-xl border border-red-400/30 bg-red-400/10 p-4">
                    <p className="flex items-center gap-2 text-xs uppercase tracking-wider text-red-300/70">
                      <AlertTriangle
                        size={15}
                      />

                      Parser error
                    </p>

                    <p className="mt-2 whitespace-pre-wrap break-words text-sm text-red-200">
                      {job.error_message}
                    </p>
                  </div>
                )}
              </article>
            ))}
          </div>
        )}

      {!jobsQuery.isPending &&
        !jobsQuery.isError &&
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
                  jobsQuery.isFetching
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
                  jobsQuery.isFetching
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