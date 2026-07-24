import {
  useMutation,
  useQueryClient,
} from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  LoaderCircle,
  Play,
  ShieldAlert,
  X,
} from 'lucide-react'
import { useState } from 'react'

import {
  ingestEvidenceLogs,
} from '../../api/logIngestion'
import type {
  EvidenceRecord,
} from '../../types/evidence'
import type {
  LogFormat,
  LogIngestionJob,
} from '../../types/logIngestion'

type LogIngestionDialogProps = {
  evidence: EvidenceRecord
  onClose: () => void
}

const logFormatOptions: Array<{
  value: string
  label: string
  description: string
}> = [
  {
    value: 'auto',
    label: 'Automatic detection',
    description:
      'Automatically detect JSON, JSON Lines, CSV, Syslog, or plain text.',
  },
  {
    value: 'json',
    label: 'JSON',
    description:
      'Parse a JSON object, JSON array, or an object containing an event list.',
  },
  {
    value: 'json_lines',
    label: 'JSON Lines',
    description:
      'Parse one JSON object per line, including NDJSON log files.',
  },
  {
    value: 'csv',
    label: 'CSV',
    description:
      'Parse comma-separated records containing a header row.',
  },
  {
    value: 'syslog',
    label: 'Syslog',
    description:
      'Parse supported Linux and network-device Syslog messages.',
  },
  {
    value: 'plain_text',
    label: 'Plain text',
    description:
      'Store each non-empty line as a normalized log event.',
  },
]

function formatLabel(value: string): string {
  return value
    .replace(/_/g, ' ')
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    )
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

  return `${(
    sizeBytes /
    (1024 * 1024)
  ).toFixed(2)} MB`
}

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'Not recorded'
  }

  return new Intl.DateTimeFormat(
    'en-GB',
    {
      dateStyle: 'medium',
      timeStyle: 'medium',
    },
  ).format(new Date(value))
}

function getApiErrorMessage(
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
    'The evidence file could not be ' +
    'processed by the log parser.'
  )
}

export function LogIngestionDialog({
  evidence,
  onClose,
}: LogIngestionDialogProps) {
  const queryClient = useQueryClient()

  const [
    selectedFormat,
    setSelectedFormat,
  ] = useState<string>('auto')

  const [
    ingestionResult,
    setIngestionResult,
  ] =
    useState<LogIngestionJob | null>(
      null,
    )

  const [
    errorMessage,
    setErrorMessage,
  ] = useState('')

  const ingestionMutation = useMutation({
    mutationFn: () =>
      ingestEvidenceLogs(
        evidence.id,
        {
          log_format: selectedFormat as LogFormat,
        },
      ),

    onSuccess: async (result) => {
      setIngestionResult(result)
      setErrorMessage('')

      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: [
            'log-events',
            'case',
            evidence.case_id,
          ],
        }),

        queryClient.invalidateQueries({
          queryKey: [
            'log-ingestion-jobs',
            'evidence',
            evidence.id,
          ],
        }),
      ])
    },

    onError: (error) => {
      setIngestionResult(null)

      setErrorMessage(
        getApiErrorMessage(error),
      )
    },
  })

  const selectedOption =
    logFormatOptions.find(
      (option) =>
        option.value === selectedFormat,
    )

  const ingestionSucceeded =
    ingestionResult?.status ===
      'completed' ||
    ingestionResult?.status ===
      'completed_with_errors'

  const ingestionFailed =
    ingestionResult?.status === 'failed'

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="log-ingestion-title"
      className="fixed inset-0 z-50 grid place-items-center bg-slate-950/85 p-4 backdrop-blur-sm"
    >
      <div className="glass max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-3xl p-6 sm:p-8">
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <div className="rounded-2xl bg-cyan/10 p-3 text-cyan">
              <FileText size={24} />
            </div>

            <div className="min-w-0">
              <p className="text-sm text-cyan">
                Log processing
              </p>

              <h2
                id="log-ingestion-title"
                className="mt-1 text-2xl font-bold"
              >
                Ingest evidence logs
              </h2>

              <p className="mt-2 break-words text-sm text-slate-400">
                {evidence.original_filename}
              </p>

              <p className="mt-1 break-all text-xs text-slate-500">
                Evidence ID: {evidence.id}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={
              ingestionMutation.isPending
            }
            aria-label="Close log ingestion dialog"
            className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:border-cyan/30 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50"
          >
            <X size={20} />
          </button>
        </div>

        <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5">
          <label
            htmlFor="log-format"
            className="text-sm font-semibold"
          >
            Parser format
          </label>

          <select
            id="log-format"
            value={selectedFormat}
            disabled={
              ingestionMutation.isPending
            }
            onChange={(event) => {
              setSelectedFormat(
                event.target.value as LogFormat
              )

              setIngestionResult(null)
              setErrorMessage('')
            }}
            className="mt-3 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60 disabled:opacity-60"
          >
            {logFormatOptions.map(
              (option) => (
                <option
                  key={option.value}
                  value={option.value}
                >
                  {option.label}
                </option>
              ),
            )}
          </select>

          <p className="mt-3 text-sm leading-6 text-slate-400">
            {selectedOption?.description}
          </p>
        </div>

        <div className="mt-5 rounded-2xl border border-amber-400/20 bg-amber-400/5 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle
              size={20}
              className="mt-0.5 shrink-0 text-amber-300"
            />

            <div>
              <p className="font-semibold text-amber-200">
                Original evidence remains unchanged
              </p>

              <p className="mt-1 text-sm leading-6 text-slate-400">
                The parser reads the preserved
                evidence and stores normalized
                records in PostgreSQL. It does not
                modify the original file or its
                SHA-256 hash.
              </p>
            </div>
          </div>
        </div>

        {errorMessage && (
          <div
            role="alert"
            className="mt-5 flex items-start gap-3 rounded-2xl border border-red-400/30 bg-red-400/10 p-5 text-red-200"
          >
            <ShieldAlert
              size={21}
              className="mt-0.5 shrink-0"
            />

            <div>
              <p className="font-semibold">
                Log ingestion failed
              </p>

              <p className="mt-1 text-sm text-red-200/80">
                {errorMessage}
              </p>
            </div>
          </div>
        )}

        {ingestionResult && (
          <div
            className={[
              'mt-5 rounded-2xl border p-5',
              ingestionSucceeded
                ? 'border-emerald-400/30 bg-emerald-400/10'
                : ingestionFailed
                  ? 'border-red-400/30 bg-red-400/10'
                  : 'border-cyan/30 bg-cyan/10',
            ].join(' ')}
          >
            <div className="flex items-start gap-3">
              {ingestionSucceeded ? (
                <CheckCircle2
                  size={22}
                  className="mt-0.5 shrink-0 text-emerald-300"
                />
              ) : ingestionFailed ? (
                <ShieldAlert
                  size={22}
                  className="mt-0.5 shrink-0 text-red-300"
                />
              ) : (
                <LoaderCircle
                  size={22}
                  className="mt-0.5 shrink-0 animate-spin text-cyan"
                />
              )}

              <div>
                <p className="font-semibold">
                  {formatLabel(
                    ingestionResult.status,
                  )}
                </p>

                <p className="mt-1 break-all text-xs text-slate-400">
                  Job ID: {ingestionResult.id}
                </p>
              </div>
            </div>

            <dl className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  Requested format
                </dt>

                <dd className="mt-2 font-semibold">
                  {formatLabel(
                    ingestionResult
                      .requested_format,
                  )}
                </dd>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  Detected format
                </dt>

                <dd className="mt-2 font-semibold">
                  {ingestionResult
                    .detected_format
                    ? formatLabel(
                        ingestionResult
                          .detected_format,
                      )
                    : 'Not detected'}
                </dd>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  Processed size
                </dt>

                <dd className="mt-2 font-semibold">
                  {formatBytes(
                    ingestionResult
                      .processed_bytes,
                  )}
                </dd>
              </div>

              <div className="rounded-xl border border-white/10 bg-slate-950/30 p-4">
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  Total records
                </dt>

                <dd className="mt-2 text-xl font-bold">
                  {ingestionResult
                    .total_records}
                </dd>
              </div>

              <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-4">
                <dt className="text-xs uppercase tracking-wider text-emerald-300/70">
                  Parsed records
                </dt>

                <dd className="mt-2 text-xl font-bold text-emerald-300">
                  {ingestionResult
                    .parsed_records}
                </dd>
              </div>

              <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-4">
                <dt className="text-xs uppercase tracking-wider text-red-300/70">
                  Failed records
                </dt>

                <dd className="mt-2 text-xl font-bold text-red-300">
                  {ingestionResult
                    .failed_records}
                </dd>
              </div>
            </dl>

            <dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-slate-500">
                  Parser
                </dt>

                <dd className="mt-1 text-slate-300">
                  {ingestionResult.parser_name}
                  {' '}v
                  {ingestionResult
                    .parser_version}
                </dd>
              </div>

              <div>
                <dt className="text-slate-500">
                  Completed
                </dt>

                <dd className="mt-1 text-slate-300">
                  {formatDate(
                    ingestionResult
                      .completed_at,
                  )}
                </dd>
              </div>
            </dl>

            {ingestionResult.error_message && (
              <div className="mt-5 rounded-xl border border-red-400/30 bg-red-400/10 p-4">
                <p className="text-xs uppercase tracking-wider text-red-300/70">
                  Parser error
                </p>

                <p className="mt-2 whitespace-pre-wrap break-words text-sm text-red-200">
                  {
                    ingestionResult
                      .error_message
                  }
                </p>
              </div>
            )}
          </div>
        )}

        <div className="mt-6 flex flex-col-reverse gap-3 border-t border-white/10 pt-5 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={onClose}
            disabled={
              ingestionMutation.isPending
            }
            className="rounded-xl border border-white/10 px-5 py-3 text-sm font-semibold text-slate-300 transition hover:border-white/20 hover:text-white disabled:opacity-50"
          >
            Close
          </button>

          <button
            type="button"
            disabled={
              ingestionMutation.isPending
            }
            onClick={() => {
              setErrorMessage('')
              setIngestionResult(null)
              ingestionMutation.mutate()
            }}
            className="flex items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {ingestionMutation.isPending ? (
              <>
                <LoaderCircle
                  size={18}
                  className="animate-spin"
                />

                Processing logs...
              </>
            ) : (
              <>
                <Play size={18} />
                Ingest logs
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}