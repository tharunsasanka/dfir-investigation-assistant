import { useQuery } from '@tanstack/react-query'
import {
  Archive,
  ChevronLeft,
  ChevronRight,
  Clock3,
  FilePlus2,
  History,
  LoaderCircle,
  Pencil,
  ShieldAlert,
} from 'lucide-react'
import { useState } from 'react'

import { getCaseAuditEvents } from '../../api/caseAudit'
import type {
  CaseAuditEvent,
  CaseAuditEventType,
} from '../../types/caseAudit'


type CaseAuditTimelineProps = {
  caseId: string
}


const PAGE_SIZE = 20


function formatDate(value: string): string {
  return new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(new Date(value))
}


function formatFieldName(value: string): string {
  return value
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    )
}


function formatValue(value: unknown): string {
  if (value === null || value === undefined) {
    return 'None'
  }

  if (typeof value === 'boolean') {
    return value ? 'Yes' : 'No'
  }

  if (typeof value === 'object') {
    return JSON.stringify(value)
  }

  return String(value)
}


function getEventDetails(
  eventType: CaseAuditEventType,
) {
  const details = {
    created: {
      label: 'Case created',
      icon: FilePlus2,
      classes: 'text-emerald-300 bg-emerald-400/10',
    },
    updated: {
      label: 'Case updated',
      icon: Pencil,
      classes: 'text-cyan bg-cyan/10',
    },
    archived: {
      label: 'Case archived',
      icon: Archive,
      classes: 'text-red-300 bg-red-400/10',
    },
  }

  return details[eventType]
}


function getChangedFields(
  event: CaseAuditEvent,
): string[] {
  const beforeFields = Object.keys(
    event.changes.before ?? {},
  )

  const afterFields = Object.keys(
    event.changes.after ?? {},
  )

  return Array.from(
    new Set([
      ...beforeFields,
      ...afterFields,
    ]),
  )
}


export function CaseAuditTimeline({
  caseId,
}: CaseAuditTimelineProps) {
  const [page, setPage] = useState(1)

  const auditQuery = useQuery({
    queryKey: [
      'cases',
      'audit',
      caseId,
      page,
    ],
    queryFn: () =>
      getCaseAuditEvents(
        caseId,
        page,
        PAGE_SIZE,
      ),
  })

  const data = auditQuery.data
  const events = data?.items ?? []

  return (
    <article className="glass mt-6 rounded-2xl p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <History className="mt-0.5 text-cyan" />

          <div>
            <h2 className="font-semibold">
              Case audit history
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Append-only history generated from real
              case actions.
            </p>
          </div>
        </div>

        <div className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-400">
          Events:{' '}
          <span className="font-semibold text-white">
            {data?.total ?? 0}
          </span>
        </div>
      </div>

      {auditQuery.isLoading && (
        <div className="mt-6 flex items-center justify-center gap-3 rounded-xl border border-white/10 p-8 text-slate-300">
          <LoaderCircle
            size={20}
            className="animate-spin text-cyan"
          />
          Loading audit history...
        </div>
      )}

      {auditQuery.isError && (
        <div className="mt-6 flex items-start gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-red-200">
          <ShieldAlert
            size={20}
            className="mt-0.5 shrink-0"
          />

          <p className="text-sm">
            The case audit history could not be loaded.
          </p>
        </div>
      )}

      {!auditQuery.isLoading &&
        !auditQuery.isError &&
        events.length === 0 && (
          <div className="mt-6 rounded-xl border border-white/10 bg-white/5 p-6 text-center">
            <Clock3
              size={28}
              className="mx-auto text-slate-500"
            />

            <p className="mt-3 font-medium">
              No audit events recorded
            </p>

            <p className="mt-2 text-sm text-slate-400">
              Events will appear after case actions are
              performed while audit tracking is enabled.
            </p>
          </div>
        )}

      {events.length > 0 && (
        <div className="mt-6 space-y-4">
          {events.map((event) => {
            const eventDetails = getEventDetails(
              event.event_type,
            )

            const EventIcon = eventDetails.icon
            const changedFields =
              getChangedFields(event)

            return (
              <section
                key={event.id}
                className="rounded-2xl border border-white/10 bg-white/5 p-5"
              >
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div
                      className={[
                        'rounded-xl p-2',
                        eventDetails.classes,
                      ].join(' ')}
                    >
                      <EventIcon size={18} />
                    </div>

                    <div>
                      <h3 className="font-semibold">
                        {eventDetails.label}
                      </h3>

                      <p className="mt-1 text-sm text-slate-400">
                        {event.actor_full_name}
                        {' · '}
                        {event.actor_email}
                      </p>
                    </div>
                  </div>

                  <time className="text-xs text-slate-500">
                    {formatDate(event.created_at)}
                  </time>
                </div>

                {changedFields.length > 0 && (
                  <div className="mt-5 grid gap-3">
                    {changedFields.map(
                      (fieldName) => (
                        <div
                          key={fieldName}
                          className="rounded-xl border border-white/10 p-4"
                        >
                          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                            {formatFieldName(
                              fieldName,
                            )}
                          </p>

                          <div className="mt-3 grid gap-3 sm:grid-cols-2">
                            <div>
                              <p className="text-xs text-slate-500">
                                Before
                              </p>

                              <p className="mt-1 break-words text-sm text-slate-300">
                                {formatValue(
                                  event.changes
                                    .before?.[
                                    fieldName
                                  ],
                                )}
                              </p>
                            </div>

                            <div>
                              <p className="text-xs text-slate-500">
                                After
                              </p>

                              <p className="mt-1 break-words text-sm text-white">
                                {formatValue(
                                  event.changes
                                    .after?.[
                                    fieldName
                                  ],
                                )}
                              </p>
                            </div>
                          </div>
                        </div>
                      ),
                    )}
                  </div>
                )}

                <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2 border-t border-white/10 pt-4 text-xs text-slate-500">
                  <span>
                    Event ID: {event.id}
                  </span>

                  <span>
                    IP: {event.ip_address ?? 'Unavailable'}
                  </span>
                </div>
              </section>
            )
          })}
        </div>
      )}

      {data && data.pages > 1 && (
        <div className="mt-6 flex items-center justify-between gap-4">
          <p className="text-sm text-slate-400">
            Page {data.page} of {data.pages}
          </p>

          <div className="flex gap-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => {
                setPage((current) =>
                  Math.max(1, current - 1),
                )
              }}
              className="rounded-xl border border-white/10 p-2 disabled:opacity-40"
            >
              <ChevronLeft size={18} />
            </button>

            <button
              type="button"
              disabled={page >= data.pages}
              onClick={() => {
                setPage((current) =>
                  current + 1,
                )
              }}
              className="rounded-xl border border-white/10 p-2 disabled:opacity-40"
            >
              <ChevronRight size={18} />
            </button>
          </div>
        </div>
      )}
    </article>
  )
}