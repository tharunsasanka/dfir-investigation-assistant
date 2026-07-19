import { useQuery } from '@tanstack/react-query'
import {
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Download,
  FileUp,
  History,
  LoaderCircle,
  ShieldAlert,
  X,
  XCircle,
} from 'lucide-react'
import { useState } from 'react'

import {
  getEvidenceCustodyEvents,
} from '../../api/evidence'
import type {
  EvidenceCustodyEventType,
  EvidenceRecord,
} from '../../types/evidence'

type EvidenceCustodyDialogProps = {
  evidence: EvidenceRecord
  onClose: () => void
}

const PAGE_SIZE = 10

function formatDate(
  dateValue: string,
): string {
  return new Intl.DateTimeFormat(
    'en-GB',
    {
      dateStyle: 'medium',
      timeStyle: 'medium',
    },
  ).format(new Date(dateValue))
}

function formatFieldName(
  fieldName: string,
): string {
  return fieldName
    .replace(/_/g, ' ')
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    )
}

function formatValue(
  value: unknown,
): string {
  if (
    value === null ||
    value === undefined ||
    value === ''
  ) {
    return 'Not recorded'
  }

  if (typeof value === 'boolean') {
    return value ? 'Yes' : 'No'
  }

  if (typeof value === 'object') {
    return JSON.stringify(
      value,
      null,
      2,
    )
  }

  return String(value)
}

function getEventDetails(
  eventType: EvidenceCustodyEventType,
) {
  const details = {
    uploaded: {
      label: 'Evidence uploaded',
      icon: FileUp,
      classes: [
        'border-cyan/30',
        'bg-cyan/10',
        'text-cyan',
      ].join(' '),
    },

    accessed: {
      label: 'Evidence accessed',
      icon: Download,
      classes: [
        'border-sky-400/30',
        'bg-sky-400/10',
        'text-sky-300',
      ].join(' '),
    },

    integrity_verified: {
      label: 'Integrity verified',
      icon: CheckCircle2,
      classes: [
        'border-emerald-400/30',
        'bg-emerald-400/10',
        'text-emerald-300',
      ].join(' '),
    },

    integrity_failed: {
      label: 'Integrity failure',
      icon: XCircle,
      classes: [
        'border-red-400/30',
        'bg-red-400/10',
        'text-red-300',
      ].join(' '),
    },
  }

  return details[eventType]
}

export function EvidenceCustodyDialog({
  evidence,
  onClose,
}: EvidenceCustodyDialogProps) {
  const [page, setPage] =
    useState(1)

  const custodyQuery = useQuery({
    queryKey: [
      'evidence',
      'custody',
      evidence.id,
      page,
    ],

    queryFn: () =>
      getEvidenceCustodyEvents(
        evidence.id,
        page,
        PAGE_SIZE,
      ),

    retry: false,
  })

  const data = custodyQuery.data
  const events = data?.items ?? []

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="custody-dialog-title"
      className="fixed inset-0 z-50 grid place-items-center bg-slate-950/85 p-4 backdrop-blur-sm"
    >
      <div className="glass max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-3xl p-6 sm:p-8">
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <div className="rounded-2xl bg-cyan/10 p-3 text-cyan">
              <History size={24} />
            </div>

            <div className="min-w-0">
              <p className="text-sm text-cyan">
                Evidence Accountability
              </p>

              <h2
                id="custody-dialog-title"
                className="mt-1 text-2xl font-bold"
              >
                Chain of custody
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
            aria-label="Close custody history"
            className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:border-cyan/30 hover:text-cyan"
          >
            <X size={20} />
          </button>
        </div>

        <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">
            Preserved SHA-256
          </p>

          <p className="mt-2 break-all font-mono text-xs leading-5 text-cyan">
            {evidence.sha256}
          </p>
        </div>

        {custodyQuery.isLoading && (
          <div className="mt-6 flex items-center justify-center gap-3 rounded-2xl border border-white/10 p-10 text-slate-300">
            <LoaderCircle
              size={21}
              className="animate-spin text-cyan"
            />

            Loading chain of custody...
          </div>
        )}

        {custodyQuery.isError && (
          <div
            role="alert"
            className="mt-6 flex items-start gap-3 rounded-2xl border border-red-400/30 bg-red-400/10 p-5 text-red-200"
          >
            <ShieldAlert
              size={21}
              className="mt-0.5 shrink-0"
            />

            <div>
              <p className="font-semibold">
                Custody history unavailable
              </p>

              <p className="mt-1 text-sm text-red-200/80">
                The evidence custody events could
                not be loaded.
              </p>
            </div>
          </div>
        )}

        {!custodyQuery.isLoading &&
          !custodyQuery.isError &&
          events.length === 0 && (
            <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-10 text-center">
              <History
                size={32}
                className="mx-auto text-slate-500"
              />

              <p className="mt-3 font-medium">
                No custody events found
              </p>
            </div>
          )}

        {events.length > 0 && (
          <div className="mt-6 space-y-4">
            {events.map((event) => {
              const eventDetails =
                getEventDetails(
                  event.event_type,
                )

              const EventIcon =
                eventDetails.icon

              const detailEntries =
                Object.entries(
                  event.details,
                )

              return (
                <article
                  key={event.id}
                  className="rounded-2xl border border-white/10 bg-white/5 p-5"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div
                        className={[
                          'rounded-xl border p-2',
                          eventDetails.classes,
                        ].join(' ')}
                      >
                        <EventIcon size={19} />
                      </div>

                      <div>
                        <h3 className="font-semibold">
                          {eventDetails.label}
                        </h3>

                        <p className="mt-1 text-sm text-slate-400">
                          {event.actor_full_name}
                        </p>

                        <p className="mt-1 text-xs text-slate-500">
                          {event.actor_email}
                        </p>
                      </div>
                    </div>

                    <time className="text-xs text-slate-500">
                      {formatDate(
                        event.created_at,
                      )}
                    </time>
                  </div>

                  {detailEntries.length > 0 && (
                    <dl className="mt-5 grid gap-3 sm:grid-cols-2">
                      {detailEntries.map(
                        ([
                          fieldName,
                          fieldValue,
                        ]) => (
                          <div
                            key={fieldName}
                            className="rounded-xl border border-white/10 bg-slate-950/30 p-4"
                          >
                            <dt className="text-xs uppercase tracking-wider text-slate-500">
                              {formatFieldName(
                                fieldName,
                              )}
                            </dt>

                            <dd className="mt-2 whitespace-pre-wrap break-all text-sm text-slate-300">
                              {formatValue(
                                fieldValue,
                              )}
                            </dd>
                          </div>
                        ),
                      )}
                    </dl>
                  )}

                  <div className="mt-5 flex flex-wrap gap-x-6 gap-y-2 border-t border-white/10 pt-4 text-xs text-slate-500">
                    <span>
                      IP:{' '}
                      {event.ip_address ??
                        'Unavailable'}
                    </span>

                    <span className="break-all">
                      Event ID: {event.id}
                    </span>
                  </div>

                  {event.user_agent && (
                    <details className="mt-4">
                      <summary className="cursor-pointer text-xs text-slate-500 transition hover:text-slate-300">
                        Browser information
                      </summary>

                      <p className="mt-2 break-all rounded-xl border border-white/10 bg-slate-950/30 p-3 text-xs text-slate-500">
                        {event.user_agent}
                      </p>
                    </details>
                  )}
                </article>
              )
            })}
          </div>
        )}

        {data && data.pages > 1 && (
          <div className="mt-6 flex flex-wrap items-center justify-between gap-4 border-t border-white/10 pt-5">
            <p className="text-sm text-slate-400">
              Page {data.page} of{' '}
              {data.pages}
            </p>

            <div className="flex gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => {
                  setPage((current) =>
                    Math.max(
                      1,
                      current - 1,
                    ),
                  )
                }}
                className="rounded-xl border border-white/10 p-2 transition hover:border-white/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronLeft size={18} />
              </button>

              <button
                type="button"
                disabled={
                  page >= data.pages
                }
                onClick={() => {
                  setPage(
                    (current) =>
                      current + 1,
                  )
                }}
                className="rounded-xl border border-white/10 p-2 transition hover:border-white/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronRight size={18} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}